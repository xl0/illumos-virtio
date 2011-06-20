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
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/ethernet.h>

/* Please export sys/vlan.h as part of ddi */
//#include <sys/vlan.h>
#define VLAN_TAGSZ 4

#include <sys/dlpi.h>
#include <sys/taskq.h>
#include <sys/cyclic.h>

#include <sys/pattr.h>
#include <sys/strsun.h>

#include <sys/random.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>


#include "util.h"
#include "virtiovar.h"
#include "virtioreg.h"

/* Configuration registers */
#define VIRTIO_NET_CONFIG_MAC		0 /* 8bit x 6byte */
#define VIRTIO_NET_CONFIG_STATUS	6 /* 16bit */

/* Feature bits */
#define VIRTIO_NET_F_CSUM       (1 << 0) /* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM (1 << 1) /* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MAC        (1 << 5) /* Host has given MAC address. */
#define VIRTIO_NET_F_GSO        (1 << 6) /* Host handles pkts w/ any GSO type */
#define VIRTIO_NET_F_GUEST_TSO4 (1 << 7) /* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6 (1 << 8) /* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN  (1 << 9) /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO  (1 << 10) /* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4  (1 << 11) /* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6  (1 << 12) /* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN   (1 << 13) /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO   (1 << 14) /* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF  (1 << 15) /* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS     (1 << 16) /* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ    (1 << 17) /* Control channel available */
#define VIRTIO_NET_F_CTRL_RX    (1 << 18) /* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN  (1 << 19)       /* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA (1 << 20) /* Extra RX mode control support */

/* Status */
#define VIRTIO_NET_S_LINK_UP	1

/* Packet header structure */
struct virtio_net_hdr {
	uint8_t		flags;
	uint8_t		gso_type;
	uint16_t	hdr_len;
	uint16_t	gso_size;
	uint16_t	csum_start;
	uint16_t	csum_offset;
};

/* Use this header layout if VIRTIO_NET_F_MRG_RXBUF is negotiated. */
struct virtio_net_hdr_mrg {
	struct virtio_net_hdr net_hdr;
	uint16_t num_buffers;
};

#define VIRTIO_NET_HDR_F_NEEDS_CSUM	1 /* flags */
#define VIRTIO_NET_HDR_GSO_NONE		0 /* gso_type */
#define VIRTIO_NET_HDR_GSO_TCPV4	1 /* gso_type */
#define VIRTIO_NET_HDR_GSO_UDP		3 /* gso_type */
#define VIRTIO_NET_HDR_GSO_TCPV6	4 /* gso_type */
#define VIRTIO_NET_HDR_GSO_ECN		0x80 /* gso_type, |'ed */

#define VIRTIO_NET_MAX_GSO_LEN		(65536+ETHER_HDR_LEN)

/* Control virtqueue */
struct virtio_net_ctrl_cmd {
	uint8_t	class;
	uint8_t	command;
} __packed;

#define VIRTIO_NET_CTRL_RX		0
#define VIRTIO_NET_CTRL_RX_PROMISC	0
#define VIRTIO_NET_CTRL_RX_ALLMULTI	1

#define VIRTIO_NET_CTRL_MAC		1
#define VIRTIO_NET_CTRL_MAC_TABLE_SET	0

#define VIRTIO_NET_CTRL_VLAN		2
#define VIRTIO_NET_CTRL_VLAN_ADD	0
#define VIRTIO_NET_CTRL_VLAN_DEL	1

struct virtio_net_ctrl_status {
	uint8_t	ack;
} __packed;

struct virtio_net_ctrl_rx {
	uint8_t	onoff;
} __packed;

struct virtio_net_ctrl_mac_tbl {
	uint32_t nentries;
	uint8_t macs[][ETHERADDRL];
} __packed;

struct virtio_net_ctrl_vlan {
	uint16_t id;
} __packed;

static int vioif_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioif_detach(dev_info_t *, ddi_detach_cmd_t);

DDI_DEFINE_STREAM_OPS(vioif_ops,
	nulldev,		/* identify */
	nulldev,		/* probe */
	vioif_attach,		/* attach */
	vioif_detach,		/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	D_MP,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_supported /* quiesce */
);

static char vioif_ident[] = "VirtIO ethernet driver";

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	vioif_ident,		/* short description */
	&vioif_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL,
	},
};

ddi_device_acc_attr_t vioif_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,	/* virtio is always native byte order */
	DDI_STRICTORDER_ACC
};

struct vioif_buf {
	struct vioif_softc	*b_sc;
	caddr_t			b_buf;
	uint32_t		b_paddr;
	ddi_dma_handle_t	b_dmah;
	ddi_acc_handle_t	b_acch;
	frtn_t			b_frtn;
};

struct vioif_softc {
	dev_info_t		*sc_dev; /* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;

	mac_handle_t sc_mac_handle;
	mac_register_t *sc_macp;

	struct virtqueue	*sc_rx_vq;
	struct virtqueue	*sc_tx_vq;
	struct virtqueue	*sc_ctrl_vq;

	int			sc_stopped:1;
	int			sc_tx_stopped:1;
	int			sc_merge:1;

	int 			sc_mtu;

	uint8_t			sc_mac[ETHERADDRL];

	/* Rx bufs - virtio_net_hdr + the packet. */
	struct vioif_buf	**sc_rxbufs;
	int			sc_rxbuf_size;

	/* Tx bufs - virtio_net_hdr + a copy of the packet. */
	struct vioif_buf	*sc_txbufs;

	kstat_t                 *sc_intrstat;
	kmem_cache_t		*sc_rxbuf_cache;

	ulong_t			sc_rxloan;
	unsigned int		sc_rxcopy_thresh;
};

#define ETHERVLANMTU    (ETHERMAX + 4)

#define DEFAULT_MTU 	ETHERMTU
#define MAX_MTU 	65535

/* We win a bit on header alignment, but the host wins a lot
 * more on moving aligned buffers! Might need more thought. */
#define VIOIF_IP_ALIGN 0

#define VIOIF_TX_SIZE 2048

/* Same for now. */
#define VIOIF_RX_SIZE VIOIF_TX_SIZE

/* Native queue size for both rx an tx. */
#define VIOIF_RX_QLEN 0
#define VIOIF_TX_QLEN 0
#define VIOIF_CTRL_QLEN 0



static link_state_t
vioif_link_state(struct vioif_softc *sc)
{
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_STATUS) {
		if (virtio_read_device_config_2(&sc->sc_virtio,
			VIRTIO_NET_CONFIG_STATUS) & VIRTIO_NET_S_LINK_UP) {

			dev_err(sc->sc_dev, CE_NOTE, "Link up\n");
			return (LINK_STATE_UP);
		} else {
			dev_err(sc->sc_dev, CE_NOTE, "Link down\n");
			return (LINK_STATE_DOWN);
		}
	}

	dev_err(sc->sc_dev, CE_NOTE, "Link assumed up\n");

	return (LINK_STATE_UP);
}

static ddi_dma_attr_t vioif_buf_dma_attr = {
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

static ddi_device_acc_attr_t vioif_bufattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static void vioif_rx_free(caddr_t free_arg)
{
	struct vioif_buf *buf = (void *) free_arg;
	struct vioif_softc *sc = buf->b_sc;

	kmem_cache_free(sc->sc_rxbuf_cache, buf);
	atomic_dec_ulong(&sc->sc_rxloan);
}

static int vioif_rx_construct(void *buffer, void *user_arg, int kmflags)
{
	struct vioif_softc *sc = user_arg;
	struct vioif_buf *buf = buffer;
	ddi_dma_cookie_t dmac;
	unsigned int nsegments;
	size_t len;

	if (ddi_dma_alloc_handle(sc->sc_dev, &vioif_buf_dma_attr,
			DDI_DMA_SLEEP, NULL, &buf->b_dmah)) {

		dev_err(sc->sc_dev, CE_WARN,
			"Can't allocate dma handle for rx buffer");
		goto exit;
	}

	if (ddi_dma_mem_alloc(buf->b_dmah, sc->sc_rxbuf_size,
			&vioif_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &buf->b_buf, &len, &buf->b_acch)) {

		dev_err(sc->sc_dev, CE_WARN,
			"Can't allocate rx buffer");
		goto exit;
	}

	if (ddi_dma_addr_bind_handle(buf->b_dmah, NULL, buf->b_buf,
			len, DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &dmac, &nsegments)) {

		dev_err(sc->sc_dev, CE_WARN, "Can't bind tx buffer");

		goto exit;
	}

	/* We asked for a single segment */
	ASSERT(nsegments == 1);
	ASSERT(len >= VIOIF_TX_SIZE);

	buf->b_paddr = dmac.dmac_address;

	buf->b_sc = sc;
	buf->b_frtn.free_arg = (void *) buf;
	buf->b_frtn.free_func = vioif_rx_free;

	return (0);

exit:
	if (buf->b_paddr)
		ddi_dma_unbind_handle(buf->b_dmah);
	if (buf->b_acch)
		ddi_dma_mem_free(&buf->b_acch);
	if (buf->b_dmah)
		ddi_dma_free_handle(&buf->b_dmah);

	return (ENOMEM);
}

static void vioif_rx_descruct(void *buffer, void *user_arg)
{
	struct vioif_buf *buf = buffer;

	ASSERT(buf->b_paddr);
	ASSERT(buf->b_acch);
	ASSERT(buf->b_dmah);

	ddi_dma_unbind_handle(buf->b_dmah);
	ddi_dma_mem_free(&buf->b_acch);
	ddi_dma_free_handle(&buf->b_dmah);
}

static void
vioif_free_mems(struct vioif_softc *sc)
{
	int i;

	for (i = 0; i < sc->sc_tx_vq->vq_num; i++) {
		struct vioif_buf *buf = &sc->sc_txbufs[i];

		ASSERT(buf->b_paddr);
		ASSERT(buf->b_acch);
		ASSERT(buf->b_dmah);

		ddi_dma_unbind_handle(buf->b_dmah);
		ddi_dma_mem_free(&buf->b_acch);
		ddi_dma_free_handle(&buf->b_dmah);
	}

	kmem_free(sc->sc_txbufs, sizeof(struct vioif_buf) * sc->sc_tx_vq->vq_num);

	for (i = 0; i < sc->sc_rx_vq->vq_num; i++) {
		struct vioif_buf *buf = sc->sc_rxbufs[i];

		if (buf)
			kmem_cache_free(sc->sc_rxbuf_cache, buf);
	}
	kmem_free(sc->sc_rxbufs, sizeof(struct vioif_buf *) * sc->sc_rx_vq->vq_num);
}

static int
vioif_alloc_mems(struct vioif_softc *sc)
{
	int i, txqsize, rxqsize;
	size_t len;
	ddi_dma_cookie_t dmac;
	unsigned int nsegments;

	txqsize = sc->sc_tx_vq->vq_num;
	rxqsize = sc->sc_rx_vq->vq_num;

	sc->sc_txbufs = kmem_zalloc(sizeof(struct vioif_buf) * txqsize,
				KM_SLEEP);
	if (!sc->sc_txbufs) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to allocate the tx buffers array");
		goto exit;
	}

	/*
	 * We don't allocate the rx vioif_buffs, just the pointers.
	 * There might be more vioif_buffs loaned upstream
	 */
	sc->sc_rxbufs = kmem_zalloc(sizeof(struct vioif_buf *) * rxqsize, KM_SLEEP);
	if (!sc->sc_rxbufs) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to allocate the rx buffers pointer array");
		goto exit_rxalloc;
	}

	for (i = 0 ; i < txqsize; i++) {
		struct vioif_buf *buf = &sc->sc_txbufs[i];

		if (ddi_dma_alloc_handle(sc->sc_dev, &vioif_buf_dma_attr,
			DDI_DMA_SLEEP, NULL, &buf->b_dmah)) {

			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate dma handle for tx buffer %d", i);
			goto exit_tx;
		}

		if (ddi_dma_mem_alloc(buf->b_dmah, VIOIF_TX_SIZE,
			&vioif_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &buf->b_buf, &len, &buf->b_acch)) {

			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate tx buffer %d", i);
			goto exit_tx;
		}

		if (ddi_dma_addr_bind_handle(buf->b_dmah, NULL, buf->b_buf,
			len, DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &dmac, &nsegments)) {

			dev_err(sc->sc_dev, CE_WARN, "Can't bind tx buffer %d", i);
			goto exit_tx;
		}

		/* We asked for a single segment */
		ASSERT(nsegments == 1);
		ASSERT(len >= VIOIF_TX_SIZE);

		buf->b_paddr = dmac.dmac_address;
	}

	return (0);

exit_tx:
	for (i = 0; i < txqsize; i++) {
		struct vioif_buf *buf = &sc->sc_txbufs[i];

		if (buf->b_paddr)
			ddi_dma_unbind_handle(buf->b_dmah);
		if (buf->b_acch)
			ddi_dma_mem_free(&buf->b_acch);
		if (buf->b_dmah)
			ddi_dma_free_handle(&buf->b_dmah);
	}

exit_rxalloc:
	kmem_free(sc->sc_txbufs, sizeof(struct vioif_buf) * txqsize);
exit:
	return (ENOMEM);
}

int
vioif_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	return (DDI_SUCCESS);
}

int
vioif_promisc(void *arg, boolean_t on)
{
	return (DDI_SUCCESS);
}

int
vioif_unicst(void *arg, const uint8_t *macaddr)
{
	return (DDI_FAILURE);
}


static int vioif_add_rx_single(struct vioif_softc *sc, int kmflag)
{
	struct vq_entry *ve;
	struct vq_entry *ve_hdr;

	struct vioif_buf *buf;

	ve_hdr = vq_alloc_entry(sc->sc_rx_vq);
	if (!ve_hdr) {
		/* Out of free descriptors - ring already full. */
		goto exit_hdr;
	}
	ve = vq_alloc_entry(sc->sc_rx_vq);
	if (!ve) {
		/* Out of free descriptors - ring already full. */
		goto exit_vq;
	}

	buf = sc->sc_rxbufs[ve_hdr->qe_index];

	if (!buf) {
		/* First run, allocate the buffer. */
		buf = kmem_cache_alloc(sc->sc_rxbuf_cache, kmflag);
		sc->sc_rxbufs[ve_hdr->qe_index] = buf;
	}
	if (!buf) {
		dev_err(sc->sc_dev, CE_WARN, "Can't allocate rx buffer");
		goto exit_buf;
	}

	virtio_ve_set(ve_hdr, buf->b_paddr,
		sizeof(struct virtio_net_hdr), B_FALSE);

	virtio_ve_set(ve, buf->b_paddr + sizeof(struct virtio_net_hdr),
		sc->sc_rxbuf_size - sizeof(struct virtio_net_hdr),
		B_FALSE);

	ve_hdr->qe_next = ve;

	virtio_push_chain(ve_hdr, B_FALSE);

	return (0);

exit_buf:
	vq_free_entry(sc->sc_rx_vq, ve);
exit_vq:
	vq_free_entry(sc->sc_rx_vq, ve_hdr);
exit_hdr:

	return (-1);
}

static int vioif_add_rx_merge(struct vioif_softc *sc, int kmflag)
{
	struct vq_entry *ve;
	struct vioif_buf *buf;

	ve = vq_alloc_entry(sc->sc_rx_vq);
	if (!ve) {
		/* Out of free descriptors - rx ring already full. */
		return (-1);
	}

	buf = sc->sc_rxbufs[ve->qe_index];

	/* This ventry's buffer has been loaned upstream, get a new one. */
	if (!buf) {
		buf = kmem_cache_alloc(sc->sc_rxbuf_cache, kmflag);
		sc->sc_rxbufs[ve->qe_index] = buf;
	}

	if (!buf) {
		dev_err(sc->sc_dev, CE_WARN, "Can't allocate rx buffer");
		vq_free_entry(sc->sc_rx_vq, ve);
		return (-1);
	}

	virtio_ve_set(ve, buf->b_paddr + VIOIF_IP_ALIGN,
		sc->sc_rxbuf_size - VIOIF_IP_ALIGN, B_FALSE);

	virtio_push_chain(ve, B_FALSE);

	return (0);
}

static int vioif_populate_rx(struct vioif_softc *sc, int kmflag)
{
	int i = 0;
	int ret;

	if (sc->sc_merge) {
		for (;;) {
			ret = vioif_add_rx_merge(sc, kmflag);
			if (ret)
				break;
			i++;
		}
	} else {
		for (;;) {
			ret = vioif_add_rx_single(sc, kmflag);
			if (ret)
				break;
			i++;
		}
	}

	if (i)
		virtio_sync_vq(sc->sc_rx_vq);

	return (i);
}

static int vioif_rx_single(struct vioif_softc *sc)
{
	struct vq_entry *ve;
	struct vq_entry *ve_hdr;

	struct vioif_buf *buf;

	mblk_t *mp;
	size_t len;

	int i = 0;

	while ((ve_hdr = virtio_pull_chain(sc->sc_rx_vq, &len))) {

		ASSERT(ve_hdr->qe_next);
		ve = ve_hdr->qe_next;

		if (len < sizeof(struct virtio_net_hdr_mrg)) {
			cmn_err(CE_WARN, "Rx: Chain too small: %ld",
				len - sizeof(struct virtio_net_hdr_mrg));
			virtio_free_chain(ve);
			continue;
		}

		buf = sc->sc_rxbufs[ve_hdr->qe_index];
		ddi_dma_sync(buf->b_dmah, 0, len , DDI_DMA_SYNC_FORCPU);

		len -= sizeof(struct virtio_net_hdr);

		mp = allocb(len, 0);
		if (!mp) {
			cmn_err(CE_WARN, "Failed to allocale mblock!");
			virtio_free_chain(ve_hdr);
			break;
		}

		bcopy((char *)buf->b_buf + sizeof(struct virtio_net_hdr),
				mp->b_rptr, len);
		mp->b_wptr = mp->b_rptr + len;

		virtio_free_chain(ve_hdr);

		mac_rx(sc->sc_mac_handle, NULL, mp);

		i++;
	}

	return (i);
}

static int vioif_rx_merged(struct vioif_softc *sc)
{
	struct vq_entry *ve;

	struct vioif_buf *buf;

	mblk_t *mp;
	size_t len;

	int i = 0;

	while ((ve = virtio_pull_chain(sc->sc_rx_vq, &len))) {

		if (ve->qe_next) {
			cmn_err(CE_NOTE, "Merged buffer len %ld", len);
			virtio_free_chain(ve);
			break;
		}

		buf = sc->sc_rxbufs[ve->qe_index];
		ASSERT(buf);


		if (len < sizeof(struct virtio_net_hdr_mrg)) {
			cmn_err(CE_WARN, "Rx: Cnain too small: %ld",
				len - sizeof(struct virtio_net_hdr_mrg));
			virtio_free_chain(ve);
			continue;
		}

		ddi_dma_sync(buf->b_dmah, 0, len, DDI_DMA_SYNC_FORCPU);
		len -= sizeof(struct virtio_net_hdr_mrg);

		/* We copy the small packets and reuse the buffers. For
		 * bigger ones, we loan the buffers upstream. */
		if (len < sc->sc_rxcopy_thresh) {
			mp = allocb(len, 0);
			if (!mp) {
				cmn_err(CE_WARN, "Failed to allocale mblock!");
				virtio_free_chain(ve);
				break;
			}

			bcopy((char *)buf->b_buf + sizeof(struct virtio_net_hdr_mrg),
					mp->b_rptr, len);

			mp->b_wptr = mp->b_rptr + len;

		} else {
			mp = desballoc((char *)buf->b_buf +
					sizeof(struct virtio_net_hdr_mrg) +
					VIOIF_IP_ALIGN,
					len, 0, &buf->b_frtn);

			if (!mp) {
				cmn_err(CE_WARN, "Failed to allocale mblock!");
				virtio_free_chain(ve);
				break;
			}
			mp->b_wptr = mp->b_rptr + len;

			atomic_inc_ulong(&sc->sc_rxloan);
			/* Buffer loanded, we will have to allocte a new one
			 * for this slot. */
			sc->sc_rxbufs[ve->qe_index] = NULL;
		}

		virtio_free_chain(ve);
		mac_rx(sc->sc_mac_handle, NULL, mp);
		i++;
	}

	return (i);
}



static int vioif_process_rx(struct vioif_softc *sc)
{
	if (sc->sc_merge) {
		return vioif_rx_merged(sc);
	}

	return vioif_rx_single(sc);
}

static void vioif_reclaim_used_tx(struct vioif_softc *sc)
{
	struct vq_entry *ve;

	size_t len;

	int i = 0;

	while ((ve = virtio_pull_chain(sc->sc_tx_vq, &len))) {
		virtio_free_chain(ve);
		i++;
	}
	if (sc->sc_tx_stopped && i) {
		sc->sc_tx_stopped = 0;
		mac_tx_update(sc->sc_mac_handle);
	}
}

static bool
vioif_send(struct vioif_softc *sc, mblk_t *mb)
{
	struct vq_entry *ve;
	struct vq_entry *ve_hdr;


	struct vioif_buf *buf;
	struct vioif_buf *buf_hdr;
	size_t msg_size = 0;
	int hdr_len;

	hdr_len = sc->sc_merge ? sizeof(struct virtio_net_hdr_mrg) :
		sizeof(struct virtio_net_hdr);

	msg_size = msgsize(mb);
	if (msg_size > MAX_MTU) {
		dev_err(sc->sc_dev, CE_WARN, "Message too big");
		freemsg(mb);
		return (B_TRUE);
	}

	ve_hdr = vq_alloc_entry(sc->sc_tx_vq);
	if (!ve_hdr) {
		/* Out of free descriptors - try later.*/
		return (B_FALSE);
	}
	ve = vq_alloc_entry(sc->sc_tx_vq);
	if (!ve) {
		vq_free_entry(sc->sc_tx_vq, ve_hdr);
		/* Out of free descriptors - try later.*/
		return (B_FALSE);
	}

	buf_hdr = &sc->sc_txbufs[ve_hdr->qe_index];
	buf = &sc->sc_txbufs[ve->qe_index];

	memset(buf_hdr->b_buf, 0, hdr_len);
	ddi_dma_sync(buf_hdr->b_dmah, 0, hdr_len,
		DDI_DMA_SYNC_FORDEV);

	virtio_ve_set(ve_hdr, buf_hdr->b_paddr, hdr_len, B_TRUE);

	mcopymsg(mb, buf->b_buf);
	ddi_dma_sync(buf->b_dmah, 0, msg_size, DDI_DMA_SYNC_FORDEV);
	virtio_ve_set(ve, buf->b_paddr, msg_size, B_TRUE);


	ve_hdr->qe_next = ve;

	virtio_push_chain(ve_hdr, B_TRUE);

	return (B_TRUE);
}

mblk_t *
vioif_tx(void *arg, mblk_t *mp)
{
	struct vioif_softc *sc = arg;
	mblk_t	*nmp;

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!vioif_send(sc, mp)) {
			sc->sc_tx_stopped = 1;
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}

	return (mp);
}

int
vioif_start(void *arg)
{
	struct vioif_softc *sc = arg;

	mac_link_update(sc->sc_mac_handle,
		vioif_link_state(sc));

	virtio_start_vq_intr(sc->sc_rx_vq);

	return (DDI_SUCCESS);
}

void
vioif_stop(void *arg)
{
	struct vioif_softc *sc = arg;

	virtio_stop_vq_intr(sc->sc_rx_vq);
}


static int
vioif_stat(void *arg, uint_t stat, uint64_t *val)
{
	switch (stat) {
		case MAC_STAT_IFSPEED:
			/* 1 Gbit */
			*val = 1000000000ULL;
			break;
		case ETHER_STAT_LINK_DUPLEX:
			*val = LINK_DUPLEX_FULL;
			break;

		default:
			return (ENOTSUP);
	}

	return (DDI_SUCCESS);
}


static int
vioif_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
		    uint_t pr_valsize, const void *pr_val)
{
	struct vioif_softc *sc = arg;
	const uint32_t *new_mtu;
	int err;

	switch (pr_num) {
		case MAC_PROP_MTU:
			new_mtu = pr_val;

			if (*new_mtu > MAX_MTU) {
				dev_err(sc->sc_dev, CE_WARN,
					"Requested mtu (%d) out of range", *new_mtu);
				return (EINVAL);
			}

			err = mac_maxsdu_update(sc->sc_mac_handle, *new_mtu);
			if (err) {
				dev_err(sc->sc_dev, CE_WARN,
					"Failed to set the requested mtu (%d)", *new_mtu);
				return (err);
			}

			break;
		default:
			return (ENOTSUP);
	}

	return (0);
}


static int
vioif_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
		    uint_t pr_valsize, void *pr_val)
{
	return (ENOTSUP);
}

static void
vioif_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
	mac_prop_info_handle_t prh)
{
	switch (pr_num) {
		case MAC_PROP_MTU:
			mac_prop_info_set_range_uint32(prh, ETHERMIN, MAX_MTU);
			break;
		default:
			break;
	}
}

static mac_callbacks_t afe_m_callbacks = {
	MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	vioif_stat,
	vioif_start,
	vioif_stop,
	vioif_promisc,
	vioif_multicst,
	vioif_unicst,
	vioif_tx,
	NULL,		/* reserved */
	NULL,		/* mc_ioctl */
	NULL,		/* mc_getcapab */
	NULL,		/* mc_open */
	NULL,		/* mc_close */
	vioif_setprop,
	vioif_getprop,
	vioif_propinfo,
};

static int
vioif_match(dev_info_t *devinfo, ddi_acc_handle_t pconf)
{
	uint16_t vendor, device, revision, subdevice, subvendor;

	vendor = pci_config_get16(pconf, PCI_CONF_VENID);
	device = pci_config_get16(pconf, PCI_CONF_DEVID);
	revision = pci_config_get8(pconf, PCI_CONF_REVID);
	subvendor = pci_config_get16(pconf, PCI_CONF_SUBVENID);
	subdevice = pci_config_get16(pconf, PCI_CONF_SUBSYSID);

	if (vendor != PCI_VENDOR_QUMRANET) {
		dev_err(devinfo, CE_WARN,
			"Vendor ID does not match: %x, expected %x",
			vendor, PCI_VENDOR_QUMRANET);
		return (DDI_FAILURE);
	}

	if (device < PCI_DEV_VIRTIO_MIN || device > PCI_DEV_VIRTIO_MAX) {
		dev_err(devinfo, CE_WARN,
			"Device ID does not match: %x, expected"
			"between %x and %x", device, PCI_DEV_VIRTIO_MIN,
			PCI_DEV_VIRTIO_MAX);
		return (DDI_FAILURE);
	}

	if (revision != VIRTIO_PCI_ABI_VERSION) {
		dev_err(devinfo, CE_WARN,
			"Device revision does not match: %x, expected %x",
			revision, VIRTIO_PCI_ABI_VERSION);
		return (DDI_FAILURE);
	}

	if (subvendor != PCI_VENDOR_QUMRANET) {
		dev_err(devinfo, CE_WARN,
			"Sub-vendor ID does not match: %x, expected %x",
			vendor, PCI_VENDOR_QUMRANET);
		return (DDI_FAILURE);
	}

	if (subdevice != PCI_PRODUCT_VIRTIO_NETWORK) {
		dev_err(devinfo, CE_NOTE,
			"Subsystem ID does not match: %x, expected %x",
			vendor, PCI_VENDOR_QUMRANET);
		dev_err(devinfo, CE_NOTE,
			"This is a virtio device, but not virtio-net, skipping");

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
vioif_show_features(struct vioif_softc *sc, const char *prefix,
		uint32_t features)
{
	char buf[512];
	char *bufp = buf;
	char *bufend = buf + sizeof(buf);

	bufp += snprintf(bufp, bufend - bufp, prefix);

	bufp += virtio_show_features(&sc->sc_virtio,
			features, bufp, bufend - bufp);

	bufp += snprintf(bufp, bufend - bufp, "Vioif ( ");

	if (features & VIRTIO_NET_F_CSUM)
		bufp += snprintf(bufp, bufend - bufp, "CSUM ");
	if (features & VIRTIO_NET_F_GUEST_CSUM)
		bufp += snprintf(bufp, bufend - bufp, "GUEST_CSUM ");
	if (features & VIRTIO_NET_F_MAC)
		bufp += snprintf(bufp, bufend - bufp, "MAC ");
	if (features & VIRTIO_NET_F_GSO)
		bufp += snprintf(bufp, bufend - bufp, "GSO ");
	if (features & VIRTIO_NET_F_GUEST_TSO4)
		bufp += snprintf(bufp, bufend - bufp, "GUEST_TSO4 ");
	if (features & VIRTIO_NET_F_GUEST_TSO6)
		bufp += snprintf(bufp, bufend - bufp, "GUEST_TSO6 ");
	if (features & VIRTIO_NET_F_GUEST_ECN)
		bufp += snprintf(bufp, bufend - bufp, "GUEST_ECN ");
	if (features & VIRTIO_NET_F_GUEST_UFO)
		bufp += snprintf(bufp, bufend - bufp, "GUEST_UFO ");
	if (features & VIRTIO_NET_F_HOST_TSO4)
		bufp += snprintf(bufp, bufend - bufp, "HOST_TSO4 ");
	if (features & VIRTIO_NET_F_HOST_TSO6)
		bufp += snprintf(bufp, bufend - bufp, "HOST_TSO6 ");
	if (features & VIRTIO_NET_F_HOST_ECN)
		bufp += snprintf(bufp, bufend - bufp, "HOST_ECN ");
	if (features & VIRTIO_NET_F_HOST_UFO)
		bufp += snprintf(bufp, bufend - bufp, "HOST_UFO ");
	if (features & VIRTIO_NET_F_MRG_RXBUF)
		bufp += snprintf(bufp, bufend - bufp, "MRG_RXBUF ");
	if (features & VIRTIO_NET_F_STATUS)
		bufp += snprintf(bufp, bufend - bufp, "STATUS ");
	if (features & VIRTIO_NET_F_CTRL_VQ)
		bufp += snprintf(bufp, bufend - bufp, "CTRL_VQ ");
	if (features & VIRTIO_NET_F_CTRL_RX)
		bufp += snprintf(bufp, bufend - bufp, "CTRL_RX ");
	if (features & VIRTIO_NET_F_CTRL_VLAN)
		bufp += snprintf(bufp, bufend - bufp, "CTRL_VLAN ");
	if (features & VIRTIO_NET_F_CTRL_RX_EXTRA)
		bufp += snprintf(bufp, bufend - bufp, "CTRL_RX_EXTRA ");

	bufp += snprintf(bufp, bufend - bufp, ")");
	*bufp = '\0';

	dev_err(sc->sc_dev, CE_NOTE, "%s", buf);
}

/*
 * Find out which features are supported by the device and
 * choose which ones we wish to use.
 */
static int
vioif_dev_features(struct vioif_softc *sc)
{
	uint32_t host_features;

	host_features = virtio_negotiate_features(&sc->sc_virtio,
			VIRTIO_NET_F_CSUM |
			VIRTIO_NET_F_MAC |
			VIRTIO_NET_F_STATUS |
			VIRTIO_NET_F_MRG_RXBUF |
			VIRTIO_F_NOTIFY_ON_EMPTY);

	vioif_show_features(sc, "Host features: ", host_features);
	vioif_show_features(sc, "Negotiated features: ", sc->sc_virtio.sc_features);

	sc->sc_rxbuf_size = VIOIF_RX_SIZE;
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_MRG_RXBUF) {
		sc->sc_merge = 1;
		sc->sc_rxbuf_size = VIRTIO_PAGE_SIZE;
	}

	return (DDI_SUCCESS);
}

static int vioif_has_feature(struct vioif_softc *sc, uint32_t feature)
{
	return virtio_has_feature(&sc->sc_virtio, feature);
}

static void
vioif_set_mac(struct vioif_softc *sc)
{
	int i;

	for (i = 0; i < ETHERADDRL; i++) {
		virtio_write_device_config_1(&sc->sc_virtio,
			VIRTIO_NET_CONFIG_MAC + i, sc->sc_mac[i]);
	}
}

/* Get the mac address out of the hardware, or make up one. */
static void
vioif_get_mac(struct vioif_softc *sc)
{
	int i;
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_MAC) {
		for (i = 0; i < ETHERADDRL; i++) {
			sc->sc_mac[i] = virtio_read_device_config_1(
				&sc->sc_virtio,
				VIRTIO_NET_CONFIG_MAC + i);
		}
		dev_err(sc->sc_dev, CE_NOTE, "Got MAC address from host: %s",
			ether_sprintf((struct ether_addr *) sc->sc_mac));
	} else {
		/* Get a few random bytes */
		random_get_pseudo_bytes(sc->sc_mac, ETHERADDRL);
		/* Make sure it's a unicast MAC */
		sc->sc_mac[0] &= ~1;
		/* Set the "locally administered" bit */
		sc->sc_mac[1] |= 2;

		vioif_set_mac(sc);

		dev_err(sc->sc_dev, CE_NOTE, "Generated a random MAC address: %s",
			ether_sprintf((struct ether_addr *) sc->sc_mac));
	}
}


/*
 * Virtqueue interrupt handlers
 */
uint_t vioif_rx_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *) arg1;
	struct vioif_softc *sc = container_of(vsc,
			struct vioif_softc, sc_virtio);

	vioif_process_rx(sc);

	vioif_populate_rx(sc, KM_NOSLEEP);

	return DDI_INTR_CLAIMED;
}

uint_t vioif_tx_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *)arg1;
	struct vioif_softc *sc = container_of(vsc,
			struct vioif_softc, sc_virtio);

	vioif_reclaim_used_tx(sc);
	return DDI_INTR_CLAIMED;
}

static int
vioif_register_ints(struct vioif_softc *sc)
{
	int ret;

	struct virtio_int_handler vioif_vq_h[] = {
		{ vioif_rx_handler },
		{ vioif_tx_handler },
		{ NULL }
	};

	ret = virtio_register_ints(&sc->sc_virtio, NULL, vioif_vq_h);

	return ret;
}

static int
vioif_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int ret, instance;
	struct vioif_softc *sc;
	struct virtio_softc *vsc;
	mac_register_t *macp;
	ddi_acc_handle_t pci_conf;

	instance = ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		dev_err(devinfo, CE_WARN, "resume not supported yet");
		goto exit;

	default:
		dev_err(devinfo, CE_WARN, "cmd 0x%x unrecognized", cmd);
		goto exit;
	}

	sc = kmem_zalloc(sizeof (struct vioif_softc), KM_SLEEP);
	ddi_set_driver_private(devinfo, sc);

	vsc = &sc->sc_virtio;

	virtio_init(vsc);

	/* Duplicate for faster access / less typing */
	sc->sc_dev = devinfo;
	vsc->sc_dev = devinfo;


	ret = pci_config_setup(devinfo, &pci_conf);
	if (ret) {
		dev_err(devinfo, CE_WARN, "unable to setup PCI config handle");
		goto exit_pci_conf;

	}

	ret = vioif_match(devinfo, pci_conf);
	if (ret)
		goto exit_match;

	pci_config_teardown(&pci_conf);

	/*
	 * Initialize interrupt kstat.
	 */
	sc->sc_intrstat = kstat_create("vioif", instance, "intr", "controller",
		KSTAT_TYPE_INTR, 1, 0);
	if (sc->sc_intrstat == NULL) {
		dev_err(devinfo, CE_WARN, "kstat_create failed");
		goto exit_intrstat;
	}
	kstat_install(sc->sc_intrstat);


	/* map BAR 0 */
	ret = ddi_regs_map_setup(devinfo, 1,
			(caddr_t *)&sc->sc_virtio.sc_io_addr,
			0, 0, &vioif_attr, &sc->sc_virtio.sc_ioh);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "unable to map bar 0: %d", ret);
		goto exit_map;
	}


	virtio_device_reset(&sc->sc_virtio);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	ret = vioif_dev_features(sc);
	if (ret)
		goto exit_features;


	vsc->sc_nvqs = vioif_has_feature(sc, VIRTIO_NET_F_CTRL_VQ) ? 3 : 2;

	sc->sc_rxbuf_cache = kmem_cache_create("vioif-rx",
		sizeof (struct vioif_buf), 0,
		vioif_rx_construct, vioif_rx_descruct,
		NULL, sc, NULL, KM_SLEEP);
	if (!sc->sc_rxbuf_cache) {
		cmn_err(CE_NOTE, "Can't allocate the buffer cache");
		goto exit_cache;
	}

	sc->sc_rx_vq = virtio_alloc_vq(&sc->sc_virtio, 0, VIOIF_RX_QLEN, 0, "rx");
	if (!sc->sc_rx_vq)
		goto exit_alloc1;

	sc->sc_tx_vq = virtio_alloc_vq(&sc->sc_virtio, 1, VIOIF_TX_QLEN, 0, "tx");
	if (!sc->sc_rx_vq)
		goto exit_alloc2;

	if (vioif_has_feature(sc, VIRTIO_NET_F_CTRL_VQ)) {
		sc->sc_ctrl_vq = virtio_alloc_vq(&sc->sc_virtio, 2,
				VIOIF_CTRL_QLEN, 0, "ctrl");
		if (!sc->sc_ctrl_vq) {
			goto exit_alloc3;
		}
		virtio_stop_vq_intr(sc->sc_ctrl_vq);
	}

	virtio_stop_vq_intr(sc->sc_rx_vq);
	virtio_stop_vq_intr(sc->sc_tx_vq);

	if (vioif_alloc_mems(sc))
		goto exit_alloc_mems;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		dev_err(devinfo, CE_WARN, "Failed to alocate a mac_register");
		goto exit_macalloc;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = sc;
	macp->m_dip = devinfo;
	macp->m_src_addr = sc->sc_mac;
	macp->m_callbacks = &afe_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = DEFAULT_MTU;
	macp->m_margin = VLAN_TAGSZ;

	sc->sc_rxloan = 0;
	sc->sc_rxcopy_thresh = 300;
	sc->sc_macp = macp;

	/* Pre-fill the rx ring. */
	vioif_populate_rx(sc, KM_SLEEP);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);


	ret = mac_register(macp, &sc->sc_mac_handle);
	if (ret) {
		dev_err(devinfo, CE_WARN, "Failed to register the device");
		goto exit_register;
	}

	ret = vioif_register_ints(sc);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN, "Failed to allocate interrupt(s)!");
		goto exit_ints;
	}

	vioif_get_mac(sc);

	return (DDI_SUCCESS);

exit_register:
	mac_free(macp);
exit_macalloc:
	vioif_free_mems(sc);
exit_alloc_mems:
	virtio_release_ints(&sc->sc_virtio);
exit_ints:
	virtio_free_vq(sc->sc_ctrl_vq);
exit_alloc3:
	virtio_free_vq(sc->sc_tx_vq);
exit_alloc2:
	virtio_free_vq(sc->sc_rx_vq);
exit_alloc1:
	kmem_cache_destroy(sc->sc_rxbuf_cache);
exit_cache:
exit_features:
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_FAILED);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
exit_intrstat:
exit_map:
	kstat_delete(sc->sc_intrstat);
exit_match:
exit_pci_conf:
	kmem_free(sc, sizeof (struct vioif_softc));
exit:
	return (DDI_FAILURE);
}

static int
vioif_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct vioif_softc *sc = ddi_get_driver_private(devinfo);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_PM_SUSPEND:
		cmn_err(CE_WARN, "suspend not supported yet");
		return (DDI_FAILURE);

	default:
		cmn_err(CE_WARN, "cmd 0x%x unrecognized", cmd);
		return (DDI_FAILURE);
	}

	if (sc->sc_rxloan) {
		cmn_err(CE_NOTE, "Some rx buffers are still upstream, Not detaching");
		return (DDI_FAILURE);
	}

	virtio_stop_vq_intr(sc->sc_rx_vq);
	virtio_stop_vq_intr(sc->sc_tx_vq);

	virtio_release_ints(&sc->sc_virtio);

	if (mac_unregister(sc->sc_mac_handle)) {
		return (DDI_FAILURE);
	}

	mac_free(sc->sc_macp);

	vioif_free_mems(sc);
	virtio_free_vq(sc->sc_rx_vq);
	virtio_free_vq(sc->sc_tx_vq);

	virtio_device_reset(&sc->sc_virtio);

	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);

	kmem_cache_destroy(sc->sc_rxbuf_cache);
	kstat_delete(sc->sc_intrstat);
	kmem_free(sc, sizeof (struct vioif_softc));

	return (DDI_SUCCESS);
}

int
_init(void)
{
	int ret = 0;

	mac_init_ops(&vioif_ops, "vioif");
	if ((ret = mod_install(&modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&vioif_ops);
		cmn_err(CE_WARN, "Unable to install the driver");
		return (ret);
	}

	return (0);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == DDI_SUCCESS) {
		mac_fini_ops(&vioif_ops);
	}

	return (ret);
}

int
_info(struct modinfo *pModinfo)
{
	return (mod_info(&modlinkage, pModinfo));
}
