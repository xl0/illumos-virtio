
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

#include "virtiovar.h"
#include "virtioreg.h"
#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))
#define MINSEG_INDIRECT	2	/* use indirect if nsegs >= this value */
#define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))& \
				 ~(VIRTIO_PAGE_SIZE-1))

/*
 * Declarations
 */
static inline void      vq_sync_uring(struct virtio_softc *sc,
				      struct virtqueue *vq, int ops);
static inline void      vq_sync_aring(struct virtio_softc *sc,
				      struct virtqueue *vq, int ops);
static void             virtio_init_vq(struct virtio_softc *sc,
				       struct virtqueue *vq);
//static void             virtio_helper(void *arg, bus_dma_segment_t *segs,
//				      int nseg, int error);
static inline void      vq_sync_indirect(struct virtio_softc *sc,
					 struct virtqueue *vq, int slot, int ops);
static inline void      vq_sync_descs(struct virtio_softc *sc,
				      struct virtqueue *vq, int ops);
static void             vq_free_entry(struct virtqueue *vq,
				      struct vq_entry *qe);
static struct vq_entry *        vq_alloc_entry(struct virtqueue *vq); 
//static int              virtio_probe(device_t dev);
//static int              virtio_detach(device_t dev);
static int              virtio_intr(void *arg);
//static int              virtio_attach(device_t dev);

/* 
 * Add to ddi? 
 */
void
dev_err(dev_info_t *dip, int ce, char *fmt, ...)
{
	va_list ap;
	char    buf[256];

	ASSERT(dip != NULL);

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	cmn_err(ce, "%s%d: %s", ddi_driver_name(dip),
		ddi_get_instance(dip), buf);
}

void dev_panic(dev_info_t *dip, char *fmt, ...)
{
	va_list ap;
	char    buf[256];

	ASSERT(dip != NULL);

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	panic("%s%d: %s", ddi_driver_name(dip),
		ddi_get_instance(dip), buf);
}

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

#define virtio_device_reset(sc)	virtio_set_status((sc), 0)

/*
 * Reset the device.
 */
/*
 * To reset the device to a known state, do following:
 *	virtio_reset(sc);	     // this will stop the device activity
 *	<dequeue finished requests>; // virtio_dequeue() still can be called
 *	<revoke pending requests in the vqs if any>;
 *	virtio_reinit_begin(sc);     // dequeue prohibitted
 *	newfeatures = virtio_negotiate_features(sc, requestedfeatures);
 *	<some other initialization>;
 *	virtio_reinit_end(sc);	     // device activated; enqueue allowed
 * Once attached, feature negotiation can only be allowed after virtio_reset.
 */
void
virtio_reset(struct virtio_softc *sc)
{
	virtio_device_reset(sc);
}

void
virtio_reinit_start(struct virtio_softc *sc)
{
	int i;

	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);
	for (i = 0; i < sc->sc_nvqs; i++) {
		int n;
		struct virtqueue *vq = &sc->sc_vqs[i];
		ddi_put16(sc->sc_ioh,
			(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT),
			vq->vq_index);
		n = ddi_get16(sc->sc_ioh,
			(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SIZE));

		if (n == 0)	/* vq disappeared */
			continue;

		if (n != vq->vq_num) {
			dev_panic(sc->sc_dev, "virtqueue size changed, vq index %d\n",
			      vq->vq_index);
		}
		virtio_init_vq(sc, vq);
		ddi_put32(sc->sc_ioh,
			(uint32_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_ADDRESS),
			(vq->vq_dma_cookie.dmac_address / VIRTIO_PAGE_SIZE));
	}
}

void
virtio_reinit_end(struct virtio_softc *sc)
{
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);
}

/*
 * Negotiate features, save the result in sc->sc_features
 */     
uint32_t
virtio_negotiate_features(struct virtio_softc *sc, uint32_t guest_features)
{
	uint32_t features;

	features = ddi_get32(sc->sc_ioh,
		(uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_FEATURES));

	dev_err(sc->sc_dev, CE_NOTE, "host features: %x, guest features: %x",
			features, guest_features);

	features &= guest_features;
	ddi_put32(sc->sc_ioh,
		(uint32_t *) (sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_FEATURES),
		features);

	sc->sc_features = features;

	return (features);
}

void
virtio_show_features(struct virtio_softc *sc)
{
	dev_err(sc->sc_dev, CE_NOTE, "Genetic Virtio features:");
	if (sc->sc_features & VIRTIO_F_RING_INDIRECT_DESC)
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
	uint64_t r;

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
 * Interrupt handler.
 */
static int
virtio_intr(void *arg)
{
	struct virtio_softc *sc = arg;
	int isr, r = 0;

	/* check and ack the interrupt */
	isr = ddi_get8(sc->sc_ioh,
		(uint8_t *) (sc->sc_io_addr + VIRTIO_CONFIG_ISR_STATUS));
	if (isr == 0)
		return 0;

	if ((isr & VIRTIO_CONFIG_ISR_CONFIG_CHANGE) &&
	    (sc->sc_config_change != NULL))
		r = (sc->sc_config_change)(sc);
	if (sc->sc_intrhand != NULL)
		r |= (sc->sc_intrhand)(sc);

	return r;
}

/*
 * dmamap sync operations for a virtqueue.
 */
static inline void
vq_sync_descs(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
#if 0
	/* availoffset == sizeof(vring_desc)*vq_num */
	bus_dmamap_sync(sc->sc_dmat, vq->vq_dmamap, 0, vq->vq_availoffset,
			ops);
#endif
}

static inline void
vq_sync_aring(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
#if 0
	bus_dmamap_sync(sc->sc_dmat, vq->vq_dmamap,
			vq->vq_availoffset,
			offsetof(struct vring_avail, ring)
			 + vq->vq_num * sizeof(uint16_t),
			ops);
#endif
}

static inline void
vq_sync_uring(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
#if 0
	bus_dmamap_sync(sc->sc_dmat, vq->vq_dmamap,
			vq->vq_usedoffset,
			offsetof(struct vring_used, ring)
			 + vq->vq_num * sizeof(struct vring_used_elem),
			ops);
#endif
}

static inline void
vq_sync_indirect(struct virtio_softc *sc, struct virtqueue *vq, int slot,
		     int ops)
{
#if 0
	int offset = vq->vq_indirectoffset
		      + sizeof(struct vring_desc) * vq->vq_maxnsegs * slot;

	bus_dmamap_sync(sc->sc_dmat, vq->vq_dmamap,
			offset, sizeof(struct vring_desc) * vq->vq_maxnsegs,
			ops);
#endif
}

/*
 * Can be used as sc_intrhand.
 */
/*
 * Scan vq, bus_dmamap_sync for the vqs (not for the payload),
 * and calls (*vq_done)() if some entries are consumed.
 */
int
virtio_vq_intr(struct virtio_softc *sc)
{
	struct virtqueue *vq;
	int i, r = 0;

	for (i = 0; i < sc->sc_nvqs; i++) {
		vq = &sc->sc_vqs[i];
		if (vq->vq_queued) {
			vq->vq_queued = 0;
//			vq_sync_aring(sc, vq, BUS_DMASYNC_POSTWRITE);
		}
//		vq_sync_uring(sc, vq, BUS_DMASYNC_POSTREAD);
//		membar_consumer();
		if (vq->vq_used_idx != vq->vq_used->idx) {
			if (vq->vq_done)
				r |= (vq->vq_done)(vq);
		}
	}
		

	return r;
}

/*
 * Start/stop vq interrupt.  No guarantee.
 */
void
virtio_stop_vq_intr(struct virtqueue *vq)
{
	vq->vq_avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
//	vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
	vq->vq_queued++;
}

void
virtio_start_vq_intr(struct virtqueue *vq)
{
	vq->vq_avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
//	vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
	vq->vq_queued++;
}

/*
 * Initialize vq structure.
 */
static void
virtio_init_vq(struct virtio_softc *sc, struct virtqueue *vq)
{
	int i, j;
	int vq_size = vq->vq_num;

	memset(vq->vq_vaddr, 0, vq->vq_bytesize);

	/* build the indirect descriptor chain */
	if (vq->vq_indirect != NULL) {
		struct vring_desc *vd;

		for (i = 0; i < vq_size; i++) {
			vd = vq->vq_indirect;
			vd += vq->vq_maxnsegs * i;
			for (j = 0; j < vq->vq_maxnsegs-1; j++)
				vd[j].next = j + 1;
		}
	}

	/* free slot management */
	list_create(&vq->vq_freelist, sizeof(struct vq_entry),
		offsetof(struct vq_entry, qe_list));
	for (i = 0; i < vq_size; i++) {
		list_insert_tail(&vq->vq_freelist, &vq->vq_entries[i]);
//		SIMPLEQ_INSERT_TAIL(&vq->vq_freelist,
//				    &vq->vq_entries[i], qe_list);
		vq->vq_entries[i].qe_index = i;
	}
	mutex_init(&vq->vq_freelist_lock, "virtio",
			MUTEX_DRIVER, sc->sc_ipl);

	/* enqueue/dequeue status */
	vq->vq_avail_idx = 0;
	vq->vq_used_idx = 0;
	vq->vq_queued = 0;
	mutex_init(&vq->vq_aring_lock, "virtio",
			MUTEX_DRIVER, sc->sc_ipl);
	mutex_init(&vq->vq_uring_lock, "virtio",
			MUTEX_DRIVER, sc->sc_ipl);
//	vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
//	vq_sync_uring(sc, vq, BUS_DMASYNC_PREREAD);
	vq->vq_queued++;
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

static ddi_device_acc_attr_t virtio_vq_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Allocate/free a vq.
 */
int
virtio_alloc_vq(struct virtio_softc *sc,
		struct virtqueue *vq, int index, int maxnsegs,
		const char *name)
{
	int vq_size, allocsize1, allocsize2, allocsize3, allocsize = 0;
	int rsegs, r;
	unsigned int ncookies;
	size_t len;
#define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))&	\
				 ~(VIRTIO_PAGE_SIZE-1))

	memset(vq, 0, sizeof(*vq));

	ddi_put16(sc->sc_ioh,
		(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT), index);
	vq_size = ddi_get16(sc->sc_ioh,
		(uint16_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SIZE));
	if (vq_size == 0) {
		dev_err(sc->sc_dev, CE_WARN,
			 "virtqueue not exist, index %d for %s\n",
			 index, name);
		goto out;
	}
	/* allocsize1: descriptor table + avail ring + pad */
	allocsize1 = VIRTQUEUE_ALIGN(sizeof(struct vring_desc) * vq_size
				     + sizeof(uint16_t) * (2 + vq_size));
	/* allocsize2: used ring + pad */
	allocsize2 = VIRTQUEUE_ALIGN(sizeof(uint16_t) * 2
				     + sizeof(struct vring_used_elem) * vq_size);
	/* allocsize3: indirect table */
	if (sc->sc_indirect && maxnsegs >= MINSEG_INDIRECT)
		allocsize3 = sizeof(struct vring_desc) * maxnsegs * vq_size;
	else
		allocsize3 = 0;
	allocsize = allocsize1 + allocsize2 + allocsize3;


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
#if 0
	/* alloc and map the memory */
	r = bus_dmamem_alloc(sc->sc_dmat, allocsize, VIRTIO_PAGE_SIZE, 0,
			     &vq->vq_segs[0], 1, &rsegs, BUS_DMA_NOWAIT);
	if (r != 0) {
		aprint_error_dev(sc->sc_dev,
				 "virtqueue %d for %s allocation failed, "
				 "error code %d\n", index, name, r);
		goto err;
	}
	r = bus_dmamem_map(sc->sc_dmat, &vq->vq_segs[0], 1, allocsize,
			   &vq->vq_vaddr, BUS_DMA_NOWAIT);
	if (r != 0) {
		aprint_error_dev(sc->sc_dev,
				 "virtqueue %d for %s map failed, "
				 "error code %d\n", index, name, r);
		goto err;
	}
	r = bus_dmamap_create(sc->sc_dmat, allocsize, 1, allocsize, 0,
			      BUS_DMA_NOWAIT, &vq->vq_dmamap);
	if (r != 0) {
		aprint_error_dev(sc->sc_dev,
				 "virtqueue %d for %s dmamap creation failed, "
				 "error code %d\n", index, name, r);
		goto err;
	}
	r = bus_dmamap_load(sc->sc_dmat, vq->vq_dmamap,
			    vq->vq_vaddr, allocsize, NULL, BUS_DMA_NOWAIT);
	if (r != 0) {
		aprint_error_dev(sc->sc_dev,
				 "virtqueue %d for %s dmamap load failed, "
				 "error code %d\n", index, name, r);
		goto err;
	}
#endif
	/* set the vq address */
	ddi_put32(sc->sc_ioh,
		(uint32_t *) (sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_ADDRESS),
			  (vq->vq_dma_cookie.dmac_address / VIRTIO_PAGE_SIZE));

	/* remember addresses and offsets for later use */
	vq->vq_owner = sc;
	vq->vq_num = vq_size;
	vq->vq_index = index;
	vq->vq_desc = vq->vq_vaddr;
	vq->vq_availoffset = sizeof(struct vring_desc)*vq_size;
	vq->vq_avail = (void*)(((char*)vq->vq_desc) + vq->vq_availoffset);
	vq->vq_usedoffset = allocsize1;
	vq->vq_used = (void*)(((char*)vq->vq_desc) + vq->vq_usedoffset);
	if (allocsize3 > 0) {
		vq->vq_indirectoffset = allocsize1 + allocsize2;
		vq->vq_indirect = (void*)(((char*)vq->vq_desc)
					  + vq->vq_indirectoffset);
	}
	vq->vq_bytesize = allocsize;
	vq->vq_maxnsegs = maxnsegs;

	/* free slot management */
	vq->vq_entries = kmem_zalloc(sizeof(struct vq_entry)*vq_size,
				     KM_NOSLEEP);
	if (!vq->vq_entries) {
		dev_err(sc->sc_dev, CE_NOTE,
			"Failed to allocate slow array for vq %d", index);
		goto out_zalloc;
	}

	virtio_init_vq(sc, vq);

	dev_err(sc->sc_dev, CE_NOTE,
		   "allocated %u byte for virtqueue %d for %s, "
		   "size %d\n", allocsize, index, name, vq_size);
	if (allocsize3 > 0)
		dev_err(sc->sc_dev, CE_NOTE,
			   "using %d byte (%d entries) "
			   "indirect descriptors\n",
			   allocsize3, maxnsegs * vq_size);
	return 0;
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

	kmem_free(vq->vq_entries, vq->vq_bytesize);

	ddi_dma_unbind_handle(vq->vq_dma_handle);
	ddi_dma_mem_free(&vq->vq_dma_acch);
	ddi_dma_free_handle(&vq->vq_dma_handle);
/*
	bus_dmamap_unload(sc->sc_dmat, vq->vq_dmamap);
	bus_dmamap_destroy(sc->sc_dmat, vq->vq_dmamap);
	bus_dmamem_unmap(sc->sc_dmat, vq->vq_vaddr, vq->vq_bytesize);
	bus_dmamem_free(sc->sc_dmat, &vq->vq_segs[0], 1);
*/
	mutex_destroy(&vq->vq_freelist_lock);
	mutex_destroy(&vq->vq_uring_lock);
	mutex_destroy(&vq->vq_aring_lock);
//	memset(vq, 0, sizeof(*vq));

	return 0;
}

/*
 * Free descriptor management.
 */
static struct vq_entry *
vq_alloc_entry(struct virtqueue *vq)
{
	struct vq_entry *qe;

	mutex_enter(&vq->vq_freelist_lock);
	if (list_is_empty(&vq->vq_freelist)) {
		mutex_exit(&vq->vq_freelist_lock);
		return NULL;
	}
	qe = list_remove_head(&vq->vq_freelist);
//	SIMPLEQ_REMOVE_HEAD(&vq->vq_freelist, qe_list);
	mutex_exit(&vq->vq_freelist_lock);

	return qe;
}

static void
vq_free_entry(struct virtqueue *vq, struct vq_entry *qe)
{
	mutex_enter(&vq->vq_freelist_lock);
	list_insert_head(&vq->vq_freelist, qe);
	mutex_exit(&vq->vq_freelist_lock);

	return;
}

/*
 * Enqueue several dmamaps as a single request.
 */
/*
 * Typical usage:
 *  <queue size> number of followings are stored in arrays
 *  - command blocks (in dmamem) should be pre-allocated and mapped
 *  - dmamaps for command blocks should be pre-allocated and loaded
 *  - dmamaps for payload should be pre-allocated
 *      r = virtio_enqueue_prep(sc, vq, &slot);		// allocate a slot
 *	if (r)		// currently 0 or EAGAIN
 *	  return r;
 *	r = bus_dmamap_load(dmat, dmamap_payload[slot], data, count, ..);
 *	if (r) {
 *	  virtio_enqueue_abort(sc, vq, slot);
 *	  bus_dmamap_unload(dmat, dmamap_payload[slot]);
 *	  return r;
 *	}
 *	r = virtio_enqueue_reserve(sc, vq, slot, 
 *				   dmamap_payload[slot]->dm_nsegs+1);
 *							// ^ +1 for command
 *	if (r) {	// currently 0 or EAGAIN
 *	  bus_dmamap_unload(dmat, dmamap_payload[slot]);
 *	  return r;					// do not call abort()
 *	}
 *	<setup and prepare commands>
 *	bus_dmamap_sync(dmat, dmamap_cmd[slot],... BUS_DMASYNC_PREWRITE);
 *	bus_dmamap_sync(dmat, dmamap_payload[slot],...);
 *	virtio_enqueue(sc, vq, slot, dmamap_cmd[slot], false);
 *	virtio_enqueue(sc, vq, slot, dmamap_payload[slot], iswrite);
 *	virtio_enqueue_commit(sc, vq, slot, true);
 */

/*
 * enqueue_prep: allocate a slot number
 */
int
virtio_enqueue_prep(struct virtio_softc *sc, struct virtqueue *vq, int *slotp)
{
	struct vq_entry *qe1;

	ASSERT(slotp != NULL);

	qe1 = vq_alloc_entry(vq);
	if (qe1 == NULL)
		return EAGAIN;
	/* next slot is not allocated yet */
	qe1->qe_next = -1;
	*slotp = qe1->qe_index;

	return 0;
}

/*
 * enqueue_reserve: allocate remaining slots and build the descriptor chain.
 */
int
virtio_enqueue_reserve(struct virtio_softc *sc, struct virtqueue *vq,
		       int slot, int nsegs)
{
	int indirect;
	struct vq_entry *qe1 = &vq->vq_entries[slot];

	ASSERT(qe1->qe_next == -1);
	ASSERT(1 <= nsegs && nsegs <= vq->vq_num);

	if ((vq->vq_indirect != NULL) &&
	    (nsegs >= MINSEG_INDIRECT) &&
	    (nsegs <= vq->vq_maxnsegs))
		indirect = 1;
	else
		indirect = 0;
	qe1->qe_indirect = indirect;

	if (indirect) {
		struct vring_desc *vd;
		int i;

		vd = &vq->vq_desc[qe1->qe_index];
		vd->addr = vq->vq_dma_cookie.dmac_address
			+ vq->vq_indirectoffset;
		vd->addr += sizeof(struct vring_desc)
			* vq->vq_maxnsegs * qe1->qe_index;
		vd->len = sizeof(struct vring_desc) * nsegs;
		vd->flags = VRING_DESC_F_INDIRECT;

		vd = vq->vq_indirect;
		vd += vq->vq_maxnsegs * qe1->qe_index;
		qe1->qe_desc_base = vd;

		for (i = 0; i < nsegs-1; i++) {
			vd[i].flags = VRING_DESC_F_NEXT;
		}
		vd[i].flags = 0;
		qe1->qe_next = 0;

		return 0;
	} else {
		struct vring_desc *vd;
		struct vq_entry *qe;
		int i, s;

		vd = &vq->vq_desc[0];
		qe1->qe_desc_base = vd;
		qe1->qe_next = qe1->qe_index;
		s = slot;
		for (i = 0; i < nsegs - 1; i++) {
			qe = vq_alloc_entry(vq);
			if (qe == NULL) {
				vd[s].flags = 0;
				virtio_enqueue_abort(sc, vq, slot);
				return EAGAIN;
			}
			vd[s].flags = VRING_DESC_F_NEXT;
			vd[s].next = qe->qe_index;
			s = qe->qe_index;
		}
		vd[s].flags = 0;

		return 0;
	}
}
/*
 * enqueue: enqueue a single dmamap.
 */
int
virtio_enqueue(struct virtio_softc *sc, struct virtqueue *vq, int slot,
	       ddi_dma_cookie_t dmac, bool write)
{

	TRACE;
	panic("Not implemented");
#if 0
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int i;
	int s = qe1->qe_next;

	ASSERT(s >= 0);
//	ASSERT(dmamap->dm_nsegs > 0);

	vd[s].addr = vq->.dmac_address
	vd[s].addr = vq->vq_dma_cookie.dmac_address

	for (i = 0; i < dmamap->dm_nsegs; i++) {
		vd[s].addr = dmamap->dm_segs[i].ds_addr;
		vd[s].len = dmamap->dm_segs[i].ds_len;
		if (!write)
			vd[s].flags |= VRING_DESC_F_WRITE;
		s = vd[s].next;
	}
	qe1->qe_next = s;
#endif

	return 0;
}

#if 0
int
virtio_enqueue_p(struct virtio_softc *sc, struct virtqueue *vq, int slot,
		 bus_dmamap_t dmamap, bus_addr_t start, bus_size_t len,
		 bool write)
{
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int s = qe1->qe_next;

	KASSERT(s >= 0);
	KASSERT(dmamap->dm_nsegs == 1); /* XXX */
	KASSERT((dmamap->dm_segs[0].ds_len > start) &&
		(dmamap->dm_segs[0].ds_len >= start + len));

	vd[s].addr = dmamap->dm_segs[0].ds_addr + start;
	vd[s].len = len;
	if (!write)
		vd[s].flags |= VRING_DESC_F_WRITE;
	qe1->qe_next = vd[s].next;

	return 0;
}
#endif

/*
 * enqueue_commit: add it to the aring.
 */
int
virtio_enqueue_commit(struct virtio_softc *sc, struct virtqueue *vq, int slot,
		      bool notifynow)
{
	TRACE;
	panic("Not implemented");
#if 0
	struct vq_entry *qe1;

	if (slot < 0) {
		mutex_enter(&vq->vq_aring_lock);
		goto notify;
	}
	vq_sync_descs(sc, vq, BUS_DMASYNC_PREWRITE);
	qe1 = &vq->vq_entries[slot];
	if (qe1->qe_indirect)
		vq_sync_indirect(sc, vq, slot, BUS_DMASYNC_PREWRITE);
	mutex_enter(&vq->vq_aring_lock);
	vq->vq_avail->ring[(vq->vq_avail_idx++) % vq->vq_num] = slot;

notify:
	if (notifynow) {
		vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
		vq_sync_uring(sc, vq, BUS_DMASYNC_PREREAD);
		membar_producer();
		vq->vq_avail->idx = vq->vq_avail_idx;
		vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
		membar_producer();
		vq->vq_queued++;
		vq_sync_uring(sc, vq, BUS_DMASYNC_POSTREAD);
		membar_consumer();
		if (!(vq->vq_used->flags & VRING_USED_F_NO_NOTIFY))
			bus_space_write_2(sc->sc_iot, sc->sc_ioh,
					  VIRTIO_CONFIG_QUEUE_NOTIFY,
					  vq->vq_index);
	}
	mutex_exit(&vq->vq_aring_lock);
#endif

	return 0;
}

/*
 * enqueue_abort: rollback.
 */
int
virtio_enqueue_abort(struct virtio_softc *sc, struct virtqueue *vq, int slot)
{
	TRACE;
	panic("Not implemented");
#if 0
	struct vq_entry *qe = &vq->vq_entries[slot];
	struct vring_desc *vd;
	int s;

	if (qe->qe_next < 0) {
		vq_free_entry(vq, qe);
		return 0;
	}

	s = slot;
	vd = &vq->vq_desc[0];
	while (vd[s].flags & VRING_DESC_F_NEXT) {
		s = vd[s].next;
		vq_free_entry(vq, qe);
		qe = &vq->vq_entries[s];
	}
	vq_free_entry(vq, qe);
#endif
	return 0;
}

/*
 * Dequeue a request.
 */
/*
 * dequeue: dequeue a request from uring; dmamap_sync for uring is
 *	    already done in the interrupt handler.
 */
int
virtio_dequeue(struct virtio_softc *sc, struct virtqueue *vq,
	       int *slotp, int *lenp)
{

	TRACE;
	panic("Not implemented");
#if 0
	uint16_t slot, usedidx;
	struct vq_entry *qe;

	if (vq->vq_used_idx == vq->vq_used->idx)
		return ENOENT;
	mutex_enter(&vq->vq_uring_lock);
	usedidx = vq->vq_used_idx++;
	mutex_exit(&vq->vq_uring_lock);
	usedidx %= vq->vq_num;
	slot = vq->vq_used->ring[usedidx].id;
	qe = &vq->vq_entries[slot];

	if (qe->qe_indirect)
		vq_sync_indirect(sc, vq, slot, BUS_DMASYNC_POSTWRITE);

	if (slotp)
		*slotp = slot;
	if (lenp)
		*lenp = vq->vq_used->ring[usedidx].len;

#endif
	return 0;
}

/*
 * dequeue_commit: complete dequeue; the slot is recycled for future use.
 *                 if you forget to call this the slot will be leaked.
 */
int
virtio_dequeue_commit(struct virtio_softc *sc, struct virtqueue *vq, int slot)
{
	TRACE;
	panic("Not implemented");
#if 0
	struct vq_entry *qe = &vq->vq_entries[slot];
	struct vring_desc *vd = &vq->vq_desc[0];
	int s = slot;

	while (vd[s].flags & VRING_DESC_F_NEXT) {
		s = vd[s].next;
		vq_free_entry(vq, qe);
		qe = &vq->vq_entries[s];
	}
	vq_free_entry(vq, qe);
#endif
	return 0;
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
