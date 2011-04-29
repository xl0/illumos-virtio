
/* Heavily based on the NetBSD virtio driver by Minoura Makoto. */
/*
 * Copyright (c) 2010 Minoura Makoto.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/avintr.h>
#include <sys/spl.h>
#include <sys/promif.h>
#include <sys/list.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>

#include "util.h"
#include "virtiovar.h"
#include "virtioreg.h"
#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))
#define MINSEG_INDIRECT	2	/* use indirect if nsegs >= this value */
#define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))& \
				 ~(VIRTIO_PAGE_SIZE-1))

/*
 * Declarations
 */

void virtio_set_status(struct virtio_softc *sc, int status)
{
	int old = 0;

	if (status != 0)
		old = ddi_get8(sc->sc_ioh,
			(uint8_t *) (sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_STATUS));

	ddi_put8(sc->sc_ioh,
		(uint8_t *) (sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_STATUS),
		status | old);
}

/*
 * Negotiate features, save the result in sc->sc_features
 */
uint32_t
virtio_negotiate_features(struct virtio_softc *sc, uint32_t guest_features)
{
	uint32_t host_features;
	uint32_t features;

	host_features = ddi_get32(sc->sc_ioh,
		(uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_FEATURES));

	dev_err(sc->sc_dev, CE_NOTE, "host features: %x, guest features: %x",
			host_features, guest_features);

	features = host_features & guest_features;
	ddi_put32(sc->sc_ioh,
		(uint32_t *) (sc->sc_io_addr + VIRTIO_CONFIG_GUEST_FEATURES),
		features);

	sc->sc_features = features;

	return (host_features);
}

void
virtio_show_features(struct virtio_softc *sc, uint32_t features)
{
	dev_err(sc->sc_dev, CE_NOTE, "Genetic Virtio features:");
	if (features & VIRTIO_F_RING_INDIRECT_DESC)
		dev_err(sc->sc_dev, CE_NOTE, "INDIRECT_DESC");
}

/*
 * Device configuration registers.
 */
uint8_t
virtio_read_device_config_1(struct virtio_softc *sc, int index)
{
	return ddi_get8(sc->sc_ioh,
		(uint8_t *) (sc->sc_io_addr + sc->sc_config_offset + index));
}

uint16_t
virtio_read_device_config_2(struct virtio_softc *sc, int index)
{
	return ddi_get16(sc->sc_ioh,
		(uint16_t *) (sc->sc_io_addr + sc->sc_config_offset + index));
}

uint32_t
virtio_read_device_config_4(struct virtio_softc *sc, int index)
{
	return ddi_get32(sc->sc_ioh,
		(uint32_t *) (sc->sc_io_addr + sc->sc_config_offset + index));
}

uint64_t
virtio_read_device_config_8(struct virtio_softc *sc, int index)
{
	return ddi_get64(sc->sc_ioh,
		(uint64_t *) (sc->sc_io_addr + sc->sc_config_offset + index));
}

void
virtio_write_device_config_1(struct virtio_softc *sc,
			     int index, uint8_t value)
{
	ddi_put8(sc->sc_ioh, 
		(uint8_t *) (sc->sc_io_addr + sc->sc_config_offset + index),
		value);
}

void
virtio_write_device_config_2(struct virtio_softc *sc,
			     int index, uint16_t value)
{
	ddi_put16(sc->sc_ioh,
		 (uint16_t *) (sc->sc_io_addr + sc->sc_config_offset + index),
		 value);
}

void
virtio_write_device_config_4(struct virtio_softc *sc,
			     int index, uint32_t value)
{
	ddi_put32(sc->sc_ioh,
		 (uint32_t *) (sc->sc_io_addr + sc->sc_config_offset + index),
		 value);
}

void
virtio_write_device_config_8(struct virtio_softc *sc,
			     int index, uint64_t value)
{
	ddi_put64(sc->sc_ioh,
		(uint64_t *) (sc->sc_io_addr + sc->sc_config_offset + index),
		value);
}

/*
 * Start/stop vq interrupt.  No guarantee.
 */
void
virtio_stop_vq_intr(struct virtqueue *vq)
{
	vq->vq_avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
}

void
virtio_start_vq_intr(struct virtqueue *vq)
{
	vq->vq_avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
}

static ddi_dma_attr_t virtio_vq_dma_attr = {
	DMA_ATTR_V0,   /* Version number */
	0,	       /* low address */
	0xFFFFFFFF,    /* high address */
	0xFFFFFFFF,    /* counter register max */
	VIRTIO_PAGE_SIZE, /* page alignment */
	0x3F,          /* burst sizes: 1 - 32 */
	0x1,           /* minimum transfer size */
	0xFFFFFFFF,    /* max transfer size */
	0xFFFFFFFF,    /* address register max */
	1,             /* no scatter-gather */
	1,             /* device operates on bytes */
	0,             /* attr flag: set to 0 */
};

static ddi_dma_attr_t virtio_entry_dma_attr = {
	DMA_ATTR_V0,   /* Version number */
	0,	       /* low address */
	0xFFFFFFFF,    /* high address */
	0xFFFFFFFF,    /* counter register max */
	1,             /* default alignment */
	0x3F,          /* burst sizes: 1 - 32 */
	0x1,           /* minimum transfer size */
	0xFFFFFFFF,    /* max transfer size */
	0xFFFFFFFF,    /* address register max */
	1,             /* no scatter-gather */
	1,             /* device operates on bytes */
	0,             /* attr flag: set to 0 */
};

static ddi_device_acc_attr_t virtio_vq_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Initialize vq structure.
 */
static int
virtio_init_vq(struct virtio_softc *sc, struct virtqueue *vq)
{
	int i;
	int vq_size = vq->vq_num;

	/* free slot management */
	list_create(&vq->vq_freelist, sizeof(struct vq_entry),
		offsetof(struct vq_entry, qe_list));

	for (i = 0; i < vq_size; i++) {
		list_insert_tail(&vq->vq_freelist, &vq->vq_entries[i]);
		vq->vq_entries[i].qe_index = i;
		vq->vq_entries[i].qe_desc = &vq->vq_descs[i];
		vq->vq_entries[i].qe_queue = vq;
	}

	mutex_init(&vq->vq_freelist_lock, "virtio",
			MUTEX_DRIVER, sc->sc_icookie);
	mutex_init(&vq->vq_aring_lock, "virtio",
			MUTEX_DRIVER, sc->sc_icookie);
	mutex_init(&vq->vq_uring_lock, "virtio",
			MUTEX_DRIVER, sc->sc_icookie);
	return (0);
}



/*
 * Allocate/free a vq.
 */
int
virtio_alloc_vq(struct virtio_softc *sc,
		struct virtqueue *vq, int index,
		int size,
		const char *name)
{
	int vq_size, allocsize1, allocsize2, allocsize = 0;
	int r;
	unsigned int ncookies;
	size_t len;
#define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))&	\
				 ~(VIRTIO_PAGE_SIZE-1))
	TRACE;

	memset(vq, 0, sizeof(*vq));

	ddi_put16(sc->sc_ioh,
		(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT), index);
	vq_size = ddi_get16(sc->sc_ioh,
		(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SIZE));
	if (vq_size == 0) {
		dev_err(sc->sc_dev, CE_WARN,
			 "virtqueue dest not exist, index %d for %s\n",
			 index, name);
		goto out;
	}

	/* size 0 => use native vq size, good for receive queues. */
	if (size)
		vq_size = MIN(vq_size, size);

	/* allocsize1: descriptor table + avail ring + pad */
	allocsize1 = VIRTQUEUE_ALIGN(sizeof(struct vring_desc) * vq_size
				+ sizeof(struct vring_avail) +
				+ sizeof(uint16_t) * vq_size);
	/* allocsize2: used ring + pad */
	allocsize2 = VIRTQUEUE_ALIGN(sizeof(struct vring_used)
				     + sizeof(struct vring_used_elem) * vq_size);

	allocsize = allocsize1 + allocsize2;

	r = ddi_dma_alloc_handle(sc->sc_dev, &virtio_vq_dma_attr,
		DDI_DMA_SLEEP, NULL, &vq->vq_dma_handle);
	if (r) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to allocate dma handle for vq %d", index);
		goto out;
	}

	r = ddi_dma_mem_alloc(vq->vq_dma_handle, allocsize, &virtio_vq_devattr,
		DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		(caddr_t *)&vq->vq_vaddr, &len, &vq->vq_dma_acch);
	if (r) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to alocate dma memory for vq %d", index);
		goto out_alloc;
	}

	memset(vq->vq_vaddr, 0, allocsize);

	r = ddi_dma_addr_bind_handle(vq->vq_dma_handle, NULL,
		(caddr_t) vq->vq_vaddr, allocsize, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		DDI_DMA_SLEEP, NULL, &vq->vq_dma_cookie, &ncookies);
	if (r != DDI_DMA_MAPPED) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to bind dma memory for vq %d", index);
		goto out_bind;
	}

	/* We asked for a single segment */
	ASSERT(ncookies == 1);
	/* and page-ligned buffers. */
	ASSERT(vq->vq_dma_cookie.dmac_address % VIRTIO_PAGE_SIZE == 0);
	/* set the vq address */
	ddi_put32(sc->sc_ioh,
		(uint32_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_ADDRESS),
			  (vq->vq_dma_cookie.dmac_address / VIRTIO_PAGE_SIZE));

	/* remember addresses and offsets for later use */
	vq->vq_owner = sc;
	vq->vq_num = vq_size;
	vq->vq_index = index;
	vq->vq_descs = vq->vq_vaddr;
	vq->vq_availoffset = sizeof(struct vring_desc)*vq_size;
	vq->vq_avail = (void*)(((char*)vq->vq_descs) + vq->vq_availoffset);
	vq->vq_usedoffset = allocsize1;
	vq->vq_used = (void*)(((char*)vq->vq_descs) + vq->vq_usedoffset);

	/* free slot management */
	vq->vq_entries = kmem_zalloc(sizeof(struct vq_entry)*vq_size,
				     KM_NOSLEEP);
	if (!vq->vq_entries) {
		dev_err(sc->sc_dev, CE_NOTE,
			"Failed to allocate slow array for vq %d", index);
		goto out_zalloc;
	}

	if (virtio_init_vq(sc, vq))
		goto out_init;

	dev_err(sc->sc_dev, CE_NOTE,
		   "allocated %u byte for virtqueue %d for %s, "
		   "size %d\n", allocsize, index, name, vq_size);
	return 0;

out_init:
	kmem_free(vq->vq_entries, sizeof(struct vq_entry) * vq->vq_num);
out_zalloc:
	ddi_dma_unbind_handle(vq->vq_dma_handle);
out_bind:
	ddi_dma_mem_free(&vq->vq_dma_acch);
out_alloc:
	ddi_dma_free_handle(&vq->vq_dma_handle);
out:
	return (DDI_FAILURE);
}


int
virtio_free_vq(struct virtio_softc *sc, struct virtqueue *vq)
{
	struct vq_entry *qe;
	int i = 0;

	TRACE;

	/* device must be already deactivated */
	/* confirm the vq is empty */

	for (qe = list_head(&vq->vq_freelist); qe != NULL;
		qe = list_next(&vq->vq_freelist, qe)) {
		i++;
	}
	if (i != vq->vq_num) {
		dev_err(sc->sc_dev, CE_WARN, "freeing non-empty vq, index %d\n",
		       vq->vq_index);
		return (DDI_FAILURE);
	}

	/* tell device that there's no virtqueue any longer */
	ddi_put16(sc->sc_ioh,
		(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT),
		vq->vq_index);
	ddi_put16(sc->sc_ioh,
		(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SIZE), 0);

	kmem_free(vq->vq_entries, sizeof(struct vq_entry) * vq->vq_num);

	ddi_dma_unbind_handle(vq->vq_dma_handle);
	ddi_dma_mem_free(&vq->vq_dma_acch);
	ddi_dma_free_handle(&vq->vq_dma_handle);

	mutex_destroy(&vq->vq_freelist_lock);
	mutex_destroy(&vq->vq_uring_lock);
	mutex_destroy(&vq->vq_aring_lock);

	return 0;
}

/*
 * Free descriptor management.
 */
struct vq_entry *
vq_alloc_entry(struct virtqueue *vq)
{
	struct vq_entry *qe;

	mutex_enter(&vq->vq_freelist_lock);
	if (list_is_empty(&vq->vq_freelist)) {
		mutex_exit(&vq->vq_freelist_lock);
		return NULL;
	}
	qe = list_remove_head(&vq->vq_freelist);

	mutex_exit(&vq->vq_freelist_lock);

	qe->qe_next = NULL;
	qe->qe_priv = NULL;
	memset(qe->qe_desc, 0, sizeof(struct vring_desc));

	return qe;
}

void
vq_free_entry(struct virtqueue *vq, struct vq_entry *qe)
{
	mutex_enter(&vq->vq_freelist_lock);
	list_insert_head(&vq->vq_freelist, qe);
	mutex_exit(&vq->vq_freelist_lock);
}

void virtio_ve_set(struct vq_entry *qe, ddi_dma_handle_t dmah,
	uint32_t paddr, uint16_t len, void *priv, bool write)
{
	qe->qe_desc->addr = paddr;
	qe->qe_desc->len = len;
	qe->qe_desc->flags = 0;
	qe->qe_dmah = dmah;
	qe->qe_priv = priv;

	/* 'write' - from the driver's point of view*/
	if (!write) {
		qe->qe_desc->flags = VRING_DESC_F_WRITE;
	}
}

static void virtio_notify(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;

	/* Find out if we need to notify the device. */
	ddi_dma_sync(vq->vq_dma_handle, vq->vq_usedoffset,
		sizeof(struct vring_used), DDI_DMA_SYNC_FORCPU);

	if (!(vq->vq_used->flags & VRING_USED_F_NO_NOTIFY))
		ddi_put16(vsc->sc_ioh,
			(uint16_t *) (vsc->sc_io_addr +
				VIRTIO_CONFIG_QUEUE_NOTIFY),
			vq->vq_index);

}

void virtio_queue_show(struct virtqueue *vq)
{

}

void vitio_push_chain(struct vq_entry *qe)
{
	struct virtqueue *vq = qe->qe_queue;
	struct vq_entry *head = qe;
	int i = 0;

	ASSERT(qe);

	/* Bind the descs together, paddr and len should be already
	 * set with virtio_ve_set */
	do {
		if (qe->qe_next) {
			qe->qe_desc->flags |= VRING_DESC_F_NEXT;
			qe->qe_desc->next = qe->qe_next->qe_index;

		}

		i++;
		qe = qe->qe_next;
	} while (qe);

	mutex_enter(&vq->vq_aring_lock);
	/* Do an other pass, adding the descs to the ring. Now with the
	 * avail ring mutex held. */
	vq->vq_avail->ring[(vq->vq_avail_idx++) % vq->vq_num] = head->qe_index;

	/* Sync the part of the ring that has been filled. */
	/* XXX worth the trouble? Maybe just sync the whole mapping? */
	(void) ddi_dma_sync(vq->vq_dma_handle,
		vq->vq_availoffset + sizeof(struct vring_avail) +
			((sizeof(uint16_t) * vq->vq_avail->idx )),
		/*sizeof(uint16_t) * (vq->vq_avail_idx - vq->vq_avail->idx)*/ 32,
		DDI_DMA_SYNC_FORDEV);

	/* Yes, we need to make sure the device sees the idx update after
	 * it sees the ring update. */
	vq->vq_avail->idx = vq->vq_avail_idx;

	/* Sync the idx and flags */
	(void) ddi_dma_sync(vq->vq_dma_handle, vq->vq_availoffset,
		sizeof(struct vring_avail), DDI_DMA_SYNC_FORDEV);

	mutex_exit(&vq->vq_aring_lock);

	virtio_notify(vq);
}

/* Get a chain of descriptors from the used ring, if one is available. */
struct vq_entry * virtio_pull_chain(struct virtqueue *vq, size_t *len)
{
	struct vq_entry *head;
	struct vq_entry *tmp;
	int slot;
	int usedidx;
	int i = 0;

	/* Sync idx (and flags) */
	ddi_dma_sync(vq->vq_dma_handle, vq->vq_usedoffset,
		sizeof(struct vring_used), DDI_DMA_SYNC_FORCPU);

	if (vq->vq_used_idx == vq->vq_used->idx)
		return NULL;

	i++;
	mutex_enter(&vq->vq_uring_lock);
	usedidx = vq->vq_used_idx++;
	mutex_exit(&vq->vq_uring_lock);

	usedidx %= vq->vq_num;

	/* Sync the ring entry */
	ddi_dma_sync(vq->vq_dma_handle,
		vq->vq_usedoffset + sizeof(struct vring_used) +
			sizeof(struct vring_used_elem) * usedidx,
		sizeof(struct vring_used_elem), DDI_DMA_SYNC_FORCPU);

	slot = vq->vq_used->ring[usedidx].id;
	*len = vq->vq_used->ring[usedidx].len;

	/* And the descriptor */
	ddi_dma_sync(vq->vq_dma_handle,
		sizeof(struct vring_desc) * slot,
		sizeof(struct vring_desc), DDI_DMA_SYNC_FORCPU);
	head = tmp = &vq->vq_entries[slot];


	/* Sanity-check the rest of the chain. */
	while (tmp->qe_desc->flags & VRING_DESC_F_NEXT) {
		/* Sync the next descriptor */
		ddi_dma_sync(vq->vq_dma_handle,
			sizeof(struct vring_desc) * tmp->qe_next->qe_index,
			sizeof(struct vring_desc), DDI_DMA_SYNC_FORCPU);

		ASSERT(tmp->qe_next);
		ASSERT(tmp->qe_next->qe_index == tmp->qe_desc->next);

		tmp = tmp->qe_next;

		i++;
	}

	ASSERT(tmp->qe_next == NULL);

	return head;
}

void virtio_free_chain(struct vq_entry *ve)
{
	struct virtqueue *vq = ve->qe_queue;
	struct vq_entry *tmp;

	ASSERT(ve);

	while (ve->qe_next) {
		tmp = ve->qe_next;
		vq_free_entry(ve->qe_queue, ve);
		ve = tmp;
	}

	vq_free_entry(ve->qe_queue, ve);
}

void virtio_ventry_stick(struct vq_entry *first, struct vq_entry *second)
{
	first->qe_next = second;
}

/*
 * DDI dev_ops entrypoints
 */
static int virtio_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int virtio_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

/*
 * Module operations
 */
struct dev_ops virtio_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	ddi_getinfo_1to1,	/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	virtio_attach,		/* attach */
	virtio_detach,		/* detach */
	nodev,			/* reset */
	NULL,			/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"VirtIO common library module",
	&virtio_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL
	}
};


/*ARGSUSED*/
static int
virtio_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	TRACE;
	if (cmd != DDI_ATTACH && cmd != DDI_RESUME) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
virtio_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	TRACE;
	return (DDI_SUCCESS);
}

int
_init(void)
{
	TRACE;
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	TRACE;
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	TRACE;
	return (mod_info(&modlinkage, modinfop));
}
