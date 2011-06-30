/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Based on the NetBSD virtio driver by Minoura Makoto. */
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
#define	NDEVNAMES	(sizeof (virtio_device_name) / sizeof (char *))
#define	MINSEG_INDIRECT	2	/* use indirect if nsegs >= this value */

void
virtio_init(struct virtio_softc *sc)
{
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;
}

void
virtio_set_status(struct virtio_softc *sc, int status)
{
	int old = 0;

	if (status != 0)
		old = ddi_get8(sc->sc_ioh,
		    (uint8_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_DEVICE_STATUS));

	ddi_put8(sc->sc_ioh,
	    (uint8_t *)(sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_STATUS),
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
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_DEVICE_FEATURES));

	dev_err(sc->sc_dev, CE_NOTE, "host features: %x, guest features: %x",
	    host_features, guest_features);

	features = host_features & guest_features;
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_GUEST_FEATURES),
	    features);

	sc->sc_features = features;
	sc->sc_indirect = features & VIRTIO_F_RING_INDIRECT_DESC;

	return (host_features);
}

size_t
virtio_show_features(uint32_t features,
		char *buf, size_t len)
{
	char *orig_buf = buf;
	char *bufend = buf + len;

	/* LINTED E_PTRDIFF_OVERFLOW */
	buf += snprintf(buf, bufend - buf, "Generic ( ");
	if (features & VIRTIO_F_RING_INDIRECT_DESC)
		/* LINTED E_PTRDIFF_OVERFLOW */
		buf += snprintf(buf, bufend - buf, "INDIRECT_DESC ");

	/* LINTED E_PTRDIFF_OVERFLOW */
	buf += snprintf(buf, bufend - buf, ") ");

	/* LINTED E_PTRDIFF_OVERFLOW */
	return (buf - orig_buf);
}

boolean_t
virtio_has_feature(struct virtio_softc *sc, uint32_t feature)
{
	return (sc->sc_features & feature);
}

/*
 * Device configuration registers.
 */
uint8_t
virtio_read_device_config_1(struct virtio_softc *sc, int index)
{
	return ddi_get8(sc->sc_ioh,
	    (uint8_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
}

uint16_t
virtio_read_device_config_2(struct virtio_softc *sc, int index)
{
	return ddi_get16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
}

uint32_t
virtio_read_device_config_4(struct virtio_softc *sc, int index)
{
	return ddi_get32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
}

uint64_t
virtio_read_device_config_8(struct virtio_softc *sc, int index)
{
	uint64_t r;

	r = ddi_get32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset +
	    index + sizeof (uint32_t)));

	r <<= 32;

	r += ddi_get32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index));
	return (r);
}

void
virtio_write_device_config_1(struct virtio_softc *sc,
			int index, uint8_t value)
{
	ddi_put8(sc->sc_ioh,
	    (uint8_t *)(sc->sc_io_addr + sc->sc_config_offset + index), value);
}

void
virtio_write_device_config_2(struct virtio_softc *sc,
			int index, uint16_t value)
{
	ddi_put16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + sc->sc_config_offset + index), value);
}

void
virtio_write_device_config_4(struct virtio_softc *sc,
			int index, uint32_t value)
{
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index), value);
}

void
virtio_write_device_config_8(struct virtio_softc *sc,
			int index, uint64_t value)
{
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset + index),
	    value & 0xFFFFFFFF);
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + sc->sc_config_offset +
	    index + sizeof (uint32_t)), value >> 32);
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
	DMA_ATTR_V0,	/* Version number */
	0,		/* low address */
	0xFFFFFFFF,	/* high address */
	0xFFFFFFFF,	/* counter register max */
	VIRTIO_PAGE_SIZE, /* page alignment */
	0x3F,		/* burst sizes: 1 - 32 */
	0x1,		/* minimum transfer size */
	0xFFFFFFFF,	/* max transfer size */
	0xFFFFFFFF,	/* address register max */
	1,		/* no scatter-gather */
	1,		/* device operates on bytes */
	0,		/* attr flag: set to 0 */
};

static ddi_device_acc_attr_t virtio_vq_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Initialize vq structure.
 */
static void
virtio_init_vq(struct virtio_softc *sc, struct virtqueue *vq)
{
	int j;
	uint16_t i;
	int vq_size = vq->vq_num;

	/* free slot management */
	list_create(&vq->vq_freelist, sizeof (struct vq_entry),
	    offsetof(struct vq_entry, qe_list));

	for (i = 0; i < vq_size; i++) {
		list_insert_tail(&vq->vq_freelist, &vq->vq_entries[i]);
		vq->vq_entries[i].qe_index = i;
		vq->vq_entries[i].qe_desc = &vq->vq_descs[i];
		vq->vq_entries[i].qe_queue = vq;

		/* build the indirect descriptor chain */
		if (vq->vq_indirect != NULL) {
			struct vring_desc *vd = vq->vq_indirect;
			vd += vq->vq_maxnsegs * i;
			for (j = 0; j < vq->vq_maxnsegs-1; j++)
				vd[j].next = j + 1;
		}
	}

	mutex_init(&vq->vq_freelist_lock, "virtio",
	    MUTEX_DRIVER, DDI_INTR_PRI(sc->sc_intr_prio));
}



/*
 * Allocate/free a vq.
 */
struct virtqueue *
virtio_alloc_vq(struct virtio_softc *sc,
		int index,
		int size,
		int maxnsegs,
		const char *name)
{
	int vq_size, allocsize1, allocsize2, allocsize3, allocsize = 0;
	int r;
	unsigned int ncookies;
	size_t len;
	struct virtqueue *vq;

#define	VIRTQUEUE_ALIGN(n) (((n)+(VIRTIO_PAGE_SIZE-1)) & \
	    ~(VIRTIO_PAGE_SIZE-1))

	ddi_put16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT), index);
	vq_size = ddi_get16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SIZE));
	if (vq_size == 0) {
		dev_err(sc->sc_dev, CE_WARN,
		    "virtqueue dest not exist, index %d for %s\n", index, name);
		goto out;
	}

	vq = kmem_zalloc(sizeof (struct virtqueue), KM_SLEEP);
	if (!vq)
		goto out;

	/* size 0 => use native vq size, good for receive queues. */
	if (size)
		vq_size = MIN(vq_size, size);

	/* allocsize1: descriptor table + avail ring + pad */
	allocsize1 = VIRTQUEUE_ALIGN(sizeof (struct vring_desc) * vq_size +
	    sizeof (struct vring_avail) +
	    sizeof (uint16_t) * vq_size);
	/* allocsize2: used ring + pad */
	allocsize2 = VIRTQUEUE_ALIGN(sizeof (struct vring_used)
	    + sizeof (struct vring_used_elem) * vq_size);
	/* allocsize3: indirect table */
	if (sc->sc_indirect && maxnsegs >= MINSEG_INDIRECT)
		allocsize3 = sizeof (struct vring_desc) * maxnsegs * vq_size;
	else
		sc->sc_indirect = allocsize3 = 0;

	allocsize = allocsize1 + allocsize2 + allocsize3;

	r = ddi_dma_alloc_handle(sc->sc_dev, &virtio_vq_dma_attr,
	    DDI_DMA_SLEEP, NULL, &vq->vq_dma_handle);
	if (r) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate dma handle for vq %d", index);
		goto out_alloc_handle;
	}

	r = ddi_dma_mem_alloc(vq->vq_dma_handle, allocsize, &virtio_vq_devattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&vq->vq_vaddr, &len, &vq->vq_dma_acch);
	if (r) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to alocate dma memory for vq %d", index);
		goto out_alloc;
	}

	(void) memset(vq->vq_vaddr, 0, allocsize);

	r = ddi_dma_addr_bind_handle(vq->vq_dma_handle, NULL,
	    (caddr_t)vq->vq_vaddr, allocsize,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
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
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_ADDRESS),
	    (vq->vq_dma_cookie.dmac_address / VIRTIO_PAGE_SIZE));

	/* remember addresses and offsets for later use */
	vq->vq_owner = sc;
	vq->vq_num = vq_size;
	vq->vq_index = index;
	vq->vq_descs = vq->vq_vaddr;
	vq->vq_availoffset = sizeof (struct vring_desc)*vq_size;
	vq->vq_avail = (void *)(((char *)vq->vq_descs) + vq->vq_availoffset);
	vq->vq_usedoffset = allocsize1;
	vq->vq_used = (void *)(((char *)vq->vq_descs) + vq->vq_usedoffset);

	vq->vq_maxnsegs = maxnsegs;
	if (sc->sc_indirect) {
		vq->vq_indirectoffset = allocsize1 + allocsize2;
		vq->vq_indirect = (void *)(((char *)vq->vq_descs) +
		    vq->vq_indirectoffset);
	} else {
		vq->vq_indirect = NULL;
	}

	/* free slot management */
	vq->vq_entries = kmem_zalloc(sizeof (struct vq_entry) * vq_size,
	    KM_NOSLEEP);
	if (!vq->vq_entries) {
		dev_err(sc->sc_dev, CE_NOTE,
		    "Failed to allocate slow array for vq %d", index);
		goto out_zalloc;
	}

	virtio_init_vq(sc, vq);

	dev_err(sc->sc_dev, CE_NOTE,
	    "allocated %u bytes for virtqueue %d (%s), "
	    "size %d", allocsize, index, name, vq_size);
	if (sc->sc_indirect) {
		dev_err(sc->sc_dev, CE_NOTE,
		    "using %d bytes (%d entries) of indirect descriptors",
		    allocsize3, maxnsegs * vq_size);
	}

	return (vq);

out_zalloc:
	(void) ddi_dma_unbind_handle(vq->vq_dma_handle);
out_bind:
	ddi_dma_mem_free(&vq->vq_dma_acch);
out_alloc:
	ddi_dma_free_handle(&vq->vq_dma_handle);
out_alloc_handle:
	kmem_free(vq, sizeof (struct virtqueue));
out:
	return (NULL);
}


void
virtio_free_vq(struct virtqueue *vq)
{
	struct virtio_softc *sc = vq->vq_owner;

	/* tell device that there's no virtqueue any longer */
	ddi_put16(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint16_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_SELECT),
	    vq->vq_index);
	ddi_put32(sc->sc_ioh,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    (uint32_t *)(sc->sc_io_addr + VIRTIO_CONFIG_QUEUE_ADDRESS), 0);

	kmem_free(vq->vq_entries, sizeof (struct vq_entry) * vq->vq_num);

	(void) ddi_dma_unbind_handle(vq->vq_dma_handle);
	ddi_dma_mem_free(&vq->vq_dma_acch);
	ddi_dma_free_handle(&vq->vq_dma_handle);

	mutex_destroy(&vq->vq_freelist_lock);

	kmem_free(vq, sizeof (struct virtqueue));
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
		return (NULL);
	}
	qe = list_remove_head(&vq->vq_freelist);

	ASSERT(vq->vq_used_entries >= 0);
	vq->vq_used_entries++;

	mutex_exit(&vq->vq_freelist_lock);

	qe->qe_next = NULL;
	qe->ind_next = NULL;
	(void) memset(qe->qe_desc, 0, sizeof (struct vring_desc));

	return (qe);
}

void
vq_free_entry(struct virtqueue *vq, struct vq_entry *qe)
{
	mutex_enter(&vq->vq_freelist_lock);
	list_insert_head(&vq->vq_freelist, qe);
	vq->vq_used_entries--;
	ASSERT(vq->vq_used_entries >= 0);
	mutex_exit(&vq->vq_freelist_lock);
}

/*
 * We (intentionally) don't have a global vq mutex, so you are
 * responsible for external locking to avoid allocting/freeing any
 * entries before using the returned value.
 */
uint_t
vq_num_used(struct virtqueue *vq)
{
	/* vq->vq_freelist_lock would not help here. */
	return (vq->vq_used_entries);
}


void
virtio_ve_set(struct vq_entry *qe, uint64_t paddr, uint32_t len, bool write)
{
	qe->qe_desc->addr = paddr;
	qe->qe_desc->len = len;

	/* 'write' - from the driver's point of view */
	if (!write) {
		qe->qe_desc->flags |= VRING_DESC_F_WRITE;
	}
}

void
virtio_ve_set_indirect(struct vq_entry *qe, int nsegs, bool write)
{
	struct virtqueue *vq = qe->qe_queue;

	ASSERT(nsegs > 1);
	ASSERT(vq->vq_indirect);
	ASSERT(nsegs <= vq->vq_maxnsegs);

	qe->qe_desc->addr = vq->vq_dma_cookie.dmac_address +
	    vq->vq_indirectoffset;
	qe->qe_desc->addr += sizeof (struct vring_desc) *
	    vq->vq_maxnsegs * qe->qe_index;
	qe->qe_desc->len = sizeof (struct vring_desc) * nsegs;
	qe->qe_desc->flags = write ? 0 : VRING_DESC_F_WRITE;
	qe->qe_desc->flags |= VRING_DESC_F_INDIRECT;
	qe->ind_next = vq->vq_indirect;
	qe->ind_next += vq->vq_maxnsegs * qe->qe_index;
}

void
virtio_ve_add_cookie(struct vq_entry *qe, ddi_dma_handle_t dma_handle,
	ddi_dma_cookie_t dma_cookie, unsigned int ncookies, bool write)
{
	uint16_t flags = write ? 0 : VRING_DESC_F_WRITE;
	int i;

	ASSERT(qe->qe_queue->vq_indirect);

	flags |= VRING_DESC_F_NEXT;
	for (i = 0; i < ncookies; i++) {
		qe->ind_next[i].addr = dma_cookie.dmac_address;
		qe->ind_next[i].len =
		    (dma_cookie.dmac_size & 0xFFFFFFFF);
		qe->ind_next[i].flags = flags;
		ddi_dma_nextcookie(dma_handle, &dma_cookie);
	}
	qe->ind_next += ncookies;
}

void
virtio_ve_add_buf(struct vq_entry *qe, uint64_t paddr, uint32_t len,
			bool write)
{
	uint16_t flags = write ? 0 : VRING_DESC_F_WRITE;

	ASSERT(qe->qe_queue->vq_indirect);

	flags |= VRING_DESC_F_NEXT;
	qe->ind_next->addr = paddr;
	qe->ind_next->len = len;
	qe->ind_next->flags = flags;
	qe->ind_next++;
}

static void
virtio_notify(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;

	/* Find out if we need to notify the device. */
	(void) ddi_dma_sync(vq->vq_dma_handle, vq->vq_usedoffset,
	    sizeof (struct vring_used), DDI_DMA_SYNC_FORKERNEL);

	if (!(vq->vq_used->flags & VRING_USED_F_NO_NOTIFY))
		ddi_put16(vsc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(vsc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_NOTIFY),
		    vq->vq_index);
}

void
virtio_sync_vq(struct virtqueue *vq)
{
	/* Sync the part of the ring that has been filled. */
	/* XXX worth the trouble? Maybe just sync the whole mapping? */
	(void) ddi_dma_sync(vq->vq_dma_handle,
	    vq->vq_availoffset + sizeof (struct vring_avail) +
	    ((sizeof (uint16_t) * vq->vq_avail->idx)),
	    sizeof (uint16_t) * (vq->vq_avail_idx - vq->vq_avail->idx),
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Yes, we need to make sure the device sees the idx update after
	 * it sees the ring update.
	 */
	vq->vq_avail->idx = vq->vq_avail_idx;

	/* Sync the idx and flags */
	(void) ddi_dma_sync(vq->vq_dma_handle, vq->vq_availoffset,
	    sizeof (struct vring_avail), DDI_DMA_SYNC_FORDEV);

	if (vq->vq_indirect)
		(void) ddi_dma_sync(vq->vq_dma_handle, vq->vq_indirectoffset,
		    sizeof (struct vring_desc) * vq->vq_maxnsegs * vq->vq_num,
		    DDI_DMA_SYNC_FORDEV);

	virtio_notify(vq);
}

void
virtio_push_chain(struct vq_entry *qe, boolean_t sync)
{
	struct virtqueue *vq = qe->qe_queue;
	struct vq_entry *head = qe;
	int idx;

	ASSERT(qe);

	/*
	 * Bind the descs together, paddr and len should be already
	 * set with virtio_ve_set
	 */
	do {
		if (qe->qe_next) {
			qe->qe_desc->flags |= VRING_DESC_F_NEXT;
			qe->qe_desc->next = qe->qe_next->qe_index;
		}

		qe = qe->qe_next;
	} while (qe);

	/* clear for the last one */
	if (head->ind_next) {
		struct vring_desc *prev = head->ind_next - 1;
		prev->flags &= ~VRING_DESC_F_NEXT;
	}

	idx = atomic_inc_16_nv(&vq->vq_avail_idx) - 1;
	vq->vq_avail->ring[idx % vq->vq_num] = head->qe_index;

	if (sync)
		virtio_sync_vq(vq);

}

/* Get a chain of descriptors from the used ring, if one is available. */
struct vq_entry *
virtio_pull_chain(struct virtqueue *vq, size_t *len)
{
	struct vq_entry *head;
	struct vq_entry *tmp;
	int slot;
	int usedidx;

	/*
	 * Sync idx (and flags), but only if we don't have any backlog
	 * from the previous sync.
	 */
	if (vq->vq_used_idx == vq->vq_used->idx) {
		(void) ddi_dma_sync(vq->vq_dma_handle, vq->vq_usedoffset,
		    sizeof (struct vring_used), DDI_DMA_SYNC_FORKERNEL);

		/* Still nothing? Bye. */
		if (vq->vq_used_idx == vq->vq_used->idx)
			return (NULL);
	}


	usedidx = atomic_inc_16_nv(&vq->vq_used_idx) - 1;

	usedidx %= vq->vq_num;

	/* Sync the ring entry */
	(void) ddi_dma_sync(vq->vq_dma_handle,
	    vq->vq_usedoffset + sizeof (struct vring_used) +
	    sizeof (struct vring_used_elem) * usedidx,
	    sizeof (struct vring_used_elem), DDI_DMA_SYNC_FORKERNEL);

	slot = vq->vq_used->ring[usedidx].id;
	*len = vq->vq_used->ring[usedidx].len;

	/* And the descriptor */
	(void) ddi_dma_sync(vq->vq_dma_handle,
	    sizeof (struct vring_desc) * slot,
	    sizeof (struct vring_desc), DDI_DMA_SYNC_FORKERNEL);
	head = tmp = &vq->vq_entries[slot];

	/* Sync the rest of the chain */
	while (tmp->qe_next) {
		tmp = tmp->qe_next;
		(void) ddi_dma_sync(vq->vq_dma_handle,
		    sizeof (struct vring_desc) * tmp->qe_index,
		    sizeof (struct vring_desc), DDI_DMA_SYNC_FORKERNEL);
	}

	return (head);
}

void
virtio_free_chain(struct vq_entry *ve)
{
	struct vq_entry *tmp;

	ASSERT(ve);

	while (ve->qe_next) {
		tmp = ve->qe_next;
		vq_free_entry(ve->qe_queue, ve);
		ve = tmp;
	}

	vq_free_entry(ve->qe_queue, ve);
}

void
virtio_ventry_stick(struct vq_entry *first, struct vq_entry *second)
{
	first->qe_next = second;
}

static int virtio_register_msi(struct virtio_softc *sc,
		struct virtio_int_handler *config_handler,
		struct virtio_int_handler vq_handlers[],
		int intr_types)
{
	int count, actual;
	int int_type;
	int i;
	int handler_count;
	int ret;

	/* If both MSI and MSI-x are reported, prefer MSI-x. */
	int_type = DDI_INTR_TYPE_MSI;
	if (intr_types & DDI_INTR_TYPE_MSIX)
		int_type = DDI_INTR_TYPE_MSIX;

	/* Walk the handler table to get the number of handlers. */
	for (handler_count = 0;
	    vq_handlers && vq_handlers[handler_count].vh_func;
	    handler_count++)
		;

	/* +1 if there is a config change handler. */
	if (config_handler)
		handler_count++;

	/* Number of MSIs supported by the device. */
	ret = ddi_intr_get_nintrs(sc->sc_dev, int_type, &count);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_get_nintrs failed");
		goto out_nomsi;
	}

	/*
	 * Those who try to register more handlers then the device
	 * supports shall suffer.
	 */
	ASSERT(handler_count <= count);

	sc->sc_intr_htable = kmem_zalloc(
	    sizeof (ddi_intr_handle_t) * handler_count, KM_SLEEP);

	if (!sc->sc_intr_htable) {
		dev_err(sc->sc_dev, CE_WARN, "Failed to allocate MSI handles");
		goto out_nomsi;
	}

	ret = ddi_intr_alloc(sc->sc_dev, sc->sc_intr_htable, int_type, 0,
	    handler_count, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN, "Failed to allocate MSI: %d", ret);
		goto out_msi_alloc;
	}

	if (actual != handler_count) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Not enough MSI available: need %d, available %d",
		    handler_count, actual);
		goto out_msi_available;
	}

	sc->sc_intr_num = actual;

	/* Assume they are all same priority */
	ret = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_prio);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_get_pri failed");
		goto out_msi_prio;
	}

	/* Add the vq handlers */
	for (i = 0; vq_handlers[i].vh_func; i++) {
		ret = ddi_intr_add_handler(sc->sc_intr_htable[i],
		    vq_handlers[i].vh_func,
		    sc, vq_handlers[i].vh_priv);
		if (ret) {
			dev_err(sc->sc_dev, CE_WARN,
			    "ddi_intr_add_handler failed");
			/* Remove the handlers that succeeded. */
			while (--i >= 0) {
				(void) ddi_intr_remove_handler(
				    sc->sc_intr_htable[i]);
			}
			goto out_add_handlers;
		}
	}

	/* Don't forget the config handler */
	if (config_handler) {
		ret = ddi_intr_add_handler(sc->sc_intr_htable[i],
		    config_handler->vh_func,
		    sc, config_handler->vh_priv);
		if (ret) {
			dev_err(sc->sc_dev, CE_WARN,
			    "ddi_intr_add_handler failed");
			/* Remove the handlers that succeeded. */
			while (--i >= 0) {
				(void) ddi_intr_remove_handler(
				    sc->sc_intr_htable[i]);
			}
			goto out_add_handlers;
		}
	}

	ret = ddi_intr_get_cap(sc->sc_intr_htable[0],
	    &sc->sc_intr_cap);
	/* Just in case. */
	if (ret)
		sc->sc_intr_cap = 0;

	/* Enable the iterrupts. Either the whole block, or one by one. */
	if (sc->sc_intr_cap & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_enable(sc->sc_intr_htable,
		    sc->sc_intr_num);
		if (ret) {
			dev_err(sc->sc_dev, CE_WARN,
			    "Failed to enable MSI, falling back to INTx");
			goto out_enable;
		}
	} else {
		for (i = 0; i < sc->sc_intr_num; i++) {
			ret = ddi_intr_enable(sc->sc_intr_htable[i]);
			if (ret) {
				dev_err(sc->sc_dev, CE_WARN,
				    "Failed to enable MSI %d, "
				    "falling back to INTx", i);

				while (--i >= 0) {
					(void) ddi_intr_disable(
					    sc->sc_intr_htable[i]);
				}
				goto out_enable;
			}
		}
	}

	/* We know we are using MSI, so set the config offset. */
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_MSI;

	/* Bind the allocated MSI to the queues and config */

	for (i = 0; vq_handlers[i].vh_func; i++) {
		int check;
		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_SELECT), i);

		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_VECTOR), i);

		check = ddi_get16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_VECTOR));
		if (check != i) {
			dev_err(sc->sc_dev, CE_WARN, "Failed to bind haneler"
			    "for VQ %d, MSI %d. Check = %x", i, i, check);
			ret = ENODEV;
			goto out_bind;
		}
	}

	if (config_handler) {
		int check;
		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_CONFIG_VECTOR), i);

		check = ddi_get16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_CONFIG_VECTOR));
		if (check != i) {
			dev_err(sc->sc_dev, CE_WARN, "Failed to bind haneler "
			    "for Config updates, MSI %d", i);
			ret = ENODEV;
			goto out_bind;
		}
	}

	return (0);


out_bind:

	/* Unbind the vqs */
	for (i = 0; i < handler_count - 1; i++) {
		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_SELECT), i);

		ddi_put16(sc->sc_ioh,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_QUEUE_VECTOR),
		    VIRTIO_MSI_NO_VECTOR);
	}
	/* And the config */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ddi_put16(sc->sc_ioh, (uint16_t *)(sc->sc_io_addr +
	    VIRTIO_CONFIG_CONFIG_VECTOR), VIRTIO_MSI_NO_VECTOR);
out_enable:
	for (i = 0; i < handler_count; i++) {
		(void) ddi_intr_remove_handler(sc->sc_intr_htable[i]);
	}

out_add_handlers:
out_msi_prio:
out_msi_available:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(sc->sc_intr_htable[i]);
out_msi_alloc:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t) * count);
out_nomsi:

	return (ret);
}

struct virtio_handler_container {
	int nhandlers;
	struct virtio_int_handler config_handler;
	struct virtio_int_handler vq_handlers[];
};

uint_t
virtio_intx_dispatch(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *sc = (void *)arg1;
	struct virtio_handler_container *vhc = (void *)arg2;
	uint8_t isr_status;
	int i;

	isr_status = ddi_get8(sc->sc_ioh, (uint8_t *)(sc->sc_io_addr +
	    VIRTIO_CONFIG_ISR_STATUS));

	if (!isr_status)
		return (DDI_INTR_UNCLAIMED);

	if ((isr_status & VIRTIO_CONFIG_ISR_CONFIG_CHANGE) &&
	    vhc->config_handler.vh_func) {
		vhc->config_handler.vh_func((void *)sc,
		    vhc->config_handler.vh_priv);
	}

	/* Notify all handlers */
	for (i = 0; i < vhc->nhandlers; i++) {
		vhc->vq_handlers[i].vh_func((void *)sc,
		    vhc->vq_handlers[i].vh_priv);
	}

	return (DDI_INTR_CLAIMED);
}

static int
virtio_register_intx(struct virtio_softc *sc,
		struct virtio_int_handler *config_handler,
		struct virtio_int_handler vq_handlers[])
{
	int vq_handler_count;
	int config_handler_count = 0;
	int actual;
	struct virtio_handler_container *vhc;
	int ret = DDI_FAILURE;

	/* Walk the handler table to get the number of handlers. */
	for (vq_handler_count = 0;
	    vq_handlers && vq_handlers[vq_handler_count].vh_func;
	    vq_handler_count++)
		;

	/* +1 if there is a config change handler. */
	if (config_handler)
		config_handler_count = 1;

	vhc = kmem_alloc(sizeof (struct virtio_int_handler) *
	    (vq_handler_count + config_handler_count), KM_SLEEP);
	if (!vhc) {
		dev_err(sc->sc_dev, CE_WARN, "Failed to allocate memory "
		    "for the handler container");
		goto out;
	}

	vhc->nhandlers = vq_handler_count;
	(void) memcpy(vhc->vq_handlers, vq_handlers,
	    sizeof (struct virtio_int_handler) * vq_handler_count);

	if (config_handler) {
		(void) memcpy(&vhc->config_handler, config_handler,
		    sizeof (struct virtio_int_handler));
	}

	sc->sc_intr_htable = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);
	if (!sc->sc_intr_htable) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate the interrupt handle");
		goto out_handle;
	}

	ret = ddi_intr_alloc(sc->sc_dev, sc->sc_intr_htable,
	    DDI_INTR_TYPE_FIXED, 0, 1, &actual,
	    DDI_INTR_ALLOC_NORMAL);

	if (ret) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to allocate interrupt: %d", ret);
		goto out_int_alloc;
	}

	/* Can't happen, we requested 1, and ddi_intr_alloc did not fail. */
	ASSERT(actual == 1);
	sc->sc_intr_num = 1;

	ret = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_prio);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_get_pri failed");
		goto out_prio;
	}

	ret = ddi_intr_add_handler(sc->sc_intr_htable[0],
	    virtio_intx_dispatch, sc, vhc);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN, "ddi_intr_add_handler failed");
		goto out_add_handlers;
	}

	/* We know we are not using MSI, so set the config offset. */
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;

	ret = ddi_intr_enable(sc->sc_intr_htable[0]);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN,
		    "Failed to enable interrupt: %d", ret);

		goto out_enable;
	}

	return (DDI_SUCCESS);

out_enable:
	(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);
out_add_handlers:
out_prio:
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
out_int_alloc:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));
out_handle:
	kmem_free(vhc, sizeof (struct virtio_int_handler) *
	    (vq_handler_count + config_handler_count));
out:
	return (ret);
}


int
virtio_register_ints(struct virtio_softc *sc,
		struct virtio_int_handler *config_handler,
		struct virtio_int_handler vq_handlers[])
{
	int ret;
	int intr_types;

	/* Determine which types of interrupts are supported */
	ret = ddi_intr_get_supported_types(sc->sc_dev, &intr_types);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN, "Can't get supported int types");
		goto out_inttype;
	}

	/* If we have msi, let's use them. */
	if (intr_types & (DDI_INTR_TYPE_MSIX | DDI_INTR_TYPE_MSI)) {
		ret = virtio_register_msi(sc, config_handler,
		    vq_handlers, intr_types);
		if (!ret)
			return (0);
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		/* Fall back to old-fashioned interrupts. */
		dev_err(sc->sc_dev, CE_WARN,
		    "Using legacy interrupts");

		return (virtio_register_intx(sc, config_handler, vq_handlers));
	}

	dev_err(sc->sc_dev, CE_WARN,
	    "MSI failed and fixed interrupts not supported. Giving up.");
	ret = DDI_FAILURE;

out_inttype:
	return (ret);
}

void
virtio_release_ints(struct virtio_softc *sc)
{
	int i;
	int ret;

	/* We were running with MSI, unbind them. */
	if (sc->sc_config_offset == VIRTIO_CONFIG_DEVICE_CONFIG_MSI) {
		/* Unbind all vqs */
		for (i = 0; i < sc->sc_nvqs; i++) {
			ddi_put16(sc->sc_ioh,
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    (uint16_t *)(sc->sc_io_addr +
			    VIRTIO_CONFIG_QUEUE_SELECT), i);

			ddi_put16(sc->sc_ioh,
			    /* LINTED E_BAD_PTR_CAST_ALIGN */
			    (uint16_t *)(sc->sc_io_addr +
			    VIRTIO_CONFIG_QUEUE_VECTOR),
			    VIRTIO_MSI_NO_VECTOR);
		}
		/* And the config */
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		ddi_put16(sc->sc_ioh, (uint16_t *)(sc->sc_io_addr +
		    VIRTIO_CONFIG_CONFIG_VECTOR),
		    VIRTIO_MSI_NO_VECTOR);

	}

	/* Disable the iterrupts. Either the whole block, or one by one. */
	if (sc->sc_intr_cap & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_disable(sc->sc_intr_htable,
		    sc->sc_intr_num);
		if (ret) {
			dev_err(sc->sc_dev, CE_WARN,
			    "Failed to disable MSIs, won't be able to"
			    "reuse next time");
		}
	} else {
		for (i = 0; i < sc->sc_intr_num; i++) {
			ret = ddi_intr_disable(sc->sc_intr_htable[i]);
			if (ret) {
				dev_err(sc->sc_dev, CE_WARN,
				    "Failed to disable interrupt %d, "
				    "won't be able to reuse", i);

			}
		}
	}


	for (i = 0; i < sc->sc_intr_num; i++) {
		(void) ddi_intr_remove_handler(sc->sc_intr_htable[i]);
	}

	for (i = 0; i < sc->sc_intr_num; i++)
		(void) ddi_intr_free(sc->sc_intr_htable[i]);

	kmem_free(sc->sc_intr_htable,
	    sizeof (ddi_intr_handle_t) * sc->sc_intr_num);


	/* After disabling interrupts, the config offset is non-MSI. */
	sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;
}

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, /* Type of module */
	"VirtIO common library module",
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modlmisc,
		NULL
	}
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
