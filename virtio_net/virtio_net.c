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

#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>


#include "util.h"
#include "virtiovar.h"
#include "virtioreg.h"


/*
 * if_vioifreg.h:
 */

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
#if 0
	uint16_t	num_buffers; /* if VIRTIO_NET_F_MRG_RXBUF enabled */
#endif
} __packed;

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
# define VIRTIO_NET_CTRL_RX_PROMISC	0
# define VIRTIO_NET_CTRL_RX_ALLMULTI	1

#define VIRTIO_NET_CTRL_MAC		1
# define VIRTIO_NET_CTRL_MAC_TABLE_SET	0

#define VIRTIO_NET_CTRL_VLAN		2
# define VIRTIO_NET_CTRL_VLAN_ADD	0
# define VIRTIO_NET_CTRL_VLAN_DEL	1

struct virtio_net_ctrl_status {
	uint8_t	ack;
} __packed;
#define VIRTIO_NET_OK			0
#define VIRTIO_NET_ERR			1

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

static int virtio_net_attach(dev_info_t *, ddi_attach_cmd_t);
static int virtio_net_detach(dev_info_t *, ddi_detach_cmd_t);
static int virtio_net_quiesce(dev_info_t *);


DDI_DEFINE_STREAM_OPS(virtio_net_ops,
	nulldev,		/* identify */
	nulldev,		/* probe */
	virtio_net_attach,	/* attach */
	virtio_net_detach,	/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	D_MP,			/* bus_ops */
	NULL,			/* power */
	virtio_net_quiesce	/* quiesce */
);


static char virtio_net_ident[] = "VirtIO ethernet driver";

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	virtio_net_ident,	/* short description */
	&virtio_net_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL,
	},
};

ddi_device_acc_attr_t virtio_net_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC, /* virtio is always narive byte order */
	DDI_STRICTORDER_ACC
};

/*
struct vioif_softc {
	struct virtio_softc sc;
	mac_handle_t mac_handle;
	uint8_t mac_address[ETHERADDRL];
};
*/

struct mblk_desc {
	ddi_dma_cookie_t	md_dma_cookie;
	ddi_dma_handle_t	md_dma_handle;
	ddi_acc_handle_t	md_dma_acch;
	struct mblk_t		*md_mblk;
};

struct vioif_buf {
	caddr_t			b_buf;
	uint32_t		b_paddr;
	ddi_dma_handle_t	b_dmah;
	ddi_acc_handle_t	b_acch;
};

struct vioif_softc {
	dev_info_t		*sc_dev; /* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;

	mac_handle_t sc_mac_handle;
	mac_register_t *sc_macp;

	int			sc_nvqs; /* set by the user */ 
	struct virtqueue	sc_vq[3];

	int			sc_stopped;

	uint8_t			sc_mac[ETHERADDRL];
//	struct ethercom		sc_ethercom;
//	uint32_t		sc_features;
	short			sc_ifflags;

	ddi_dma_cookie_t	sc_hdr_dma_cookie;
	ddi_dma_handle_t	sc_hdr_dma_handle;
	ddi_acc_handle_t	sc_hdr_dma_acch;
	/* bus_dmamem */
//	bus_dma_segment_t	sc_hdr_segs[1];
//	struct virtio_net_hdr	*sc_rx_hdrs;
//#define sc_rx_hdrs	sc_hdrs
//	struct virtio_net_hdr	*sc_tx_hdrs;

//	struct mblk_desc	*sc_rx_mblk_descs;
//	struct mblk_desc	*sc_tx_mblk_descs;

	/* Tx bufs - virtio_net_hdr + the packet. */
	struct vioif_buf	*sc_rxbufs;
	int			sc_numrxbufs;

	/* Tx bufs - virtio_net_hdr + a copy of the packet. */
	struct vioif_buf	*sc_txbufs;
	int			sc_numtxbufs;
//	struct virtio_net_ctrl_cmd *sc_ctrl_cmd;
//	struct virtio_net_ctrl_status *sc_ctrl_status;
//	struct virtio_net_ctrl_rx *sc_ctrl_rx;
//	struct virtio_net_ctrl_mac_tbl *sc_ctrl_mac_tbl_uc;
//	struct virtio_net_ctrl_mac_tbl *sc_ctrl_mac_tbl_mc;

	/* kmem */
//	bus_dmamap_t		*sc_arrays;
//#define sc_rxhdr_dmamaps sc_arrays
//	bus_dmamap_t		*sc_txhdr_dmamaps;
//	bus_dmamap_t		*sc_rx_dmamaps;
//	bus_dmamap_t		*sc_tx_dmamaps;
//	struct mbuf		**sc_rx_mbufs;
//	struct mbuf		**sc_tx_mbufs;

//	bus_dmamap_t		sc_ctrl_cmd_dmamap;
//	bus_dmamap_t		sc_ctrl_status_dmamap;
//	bus_dmamap_t		sc_ctrl_rx_dmamap;
//	bus_dmamap_t		sc_ctrl_tbl_uc_dmamap;
//	bus_dmamap_t		sc_ctrl_tbl_mc_dmamap;

//	void			*sc_rx_softint;

//	enum {
//		FREE, INUSE, DONE
//	}			sc_ctrl_inuse;
//	kcondvar_t		sc_ctrl_wait;
	kmutex_t		sc_ctrl_wait_lock;
	kmutex_t		sc_tx_lock;

	kstat_t                 *sc_intrstat;
};

#define ETHERVLANMTU    (ETHERMAX + 4)

#define VIOIF_IP_ALIGN 0
/*
#define VIOIF_TX_SIZE (VIOIF_IP_ALIGN + \
		sizeof (struct virtio_net_hdr) + \
		ETHERVLANMTU)
*/
#define VIOIF_TX_SIZE 2048

/* Same for now. */
#define VIOIF_RX_SIZE VIOIF_TX_SIZE

#define VIOIF_PACKET_OFFSET (VIOIF_IP_ALIGN + \
		sizeof (struct virtio_net_hdr))

/* Native queue size for both rx an tx. */
#define VIOIF_RX_QLEN 0
#define VIOIF_TX_QLEN 0

//#define VIRTIO_NET_TX_MAXNSEGS		(16) /* XXX */
//#define VIRTIO_NET_CTRL_MAC_MAXENTRIES	(64) /* XXX */
/*
 * _init
 *
 * Solaris standard _init function for a device driver
 */
int
_init(void)
{
	int ret = 0;
	TRACE;

	mac_init_ops(&virtio_net_ops, "virtio_net");
	if ((ret = mod_install(&modlinkage)) != DDI_SUCCESS) {
		TRACE;
		mac_fini_ops(&virtio_net_ops);
		cmn_err(CE_WARN, "unable to install the driver");
		return (ret);
	}

	return (0);
}

/*
 * _fini
 *
 * Solaris standard _fini function for device driver
 */
int
_fini(void)
{
	int ret;
	TRACE;

	ret = mod_remove(&modlinkage);
	if (ret == DDI_SUCCESS) {
		mac_fini_ops(&virtio_net_ops);
	}

	return (ret);
}

/*
 * _info
 *
 * Solaris standard _info function for device driver
 */
int
_info(struct modinfo *pModinfo)
{
	TRACE;
	return (mod_info(&modlinkage, pModinfo));
}

static link_state_t
virtio_net_link_state(struct vioif_softc *sc)
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

static ddi_dma_attr_t virtio_net_buf_dma_attr = {
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

static ddi_device_acc_attr_t virtio_net_bufattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};



static int virtio_net_alloc_buffers(struct vioif_softc *sc)
{
	size_t len;
	unsigned int nsegments;
	int rxqsize, txqsize;
	int i;
	int r = ENOMEM;
	struct vioif_buf *buf;
	ddi_dma_cookie_t dmac;

	rxqsize = sc->sc_vq[0].vq_num;
	txqsize = sc->sc_vq[1].vq_num;

//	TRACE;

	sc->sc_rxbufs = kmem_zalloc(sizeof(struct vioif_buf) * rxqsize,
		KM_SLEEP);
	if (!sc->sc_rxbufs) {
		dev_err(sc->sc_dev, CE_WARN, "Failed to allocate rx buffers array");
		goto exit_alloc;
	}

	sc->sc_txbufs = kmem_zalloc(sizeof(struct vioif_buf) * txqsize,
		KM_SLEEP);
	if (!sc->sc_txbufs) {
		dev_err(sc->sc_dev, CE_WARN, "Failed to allocate tx buffers array");
		goto exit_alloc;
	}

	for (i = 0 ; i < rxqsize; i++) {
		buf = &sc->sc_rxbufs[i];

		if (ddi_dma_alloc_handle(sc->sc_dev, &virtio_net_buf_dma_attr,
			DDI_DMA_SLEEP, NULL, &buf->b_dmah)) {
			
			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate dma handle for rx buffer %d", i);
			goto exit;
		}

		if (ddi_dma_mem_alloc(buf->b_dmah, VIOIF_RX_SIZE,
			&virtio_net_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &buf->b_buf, &len, &buf->b_acch)) {

			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate rx buffer %d", i);
			goto exit;
		}

		if (ddi_dma_addr_bind_handle(buf->b_dmah, NULL, buf->b_buf,
			len, DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &dmac, &nsegments)) {
			
			dev_err(sc->sc_dev, CE_WARN, "Can't bind tx buffer %d", i);

			goto exit;
		}

		/* We asked for a single segment */
		ASSERT(nsegments == 1);
		ASSERT(len >= VIOIF_TX_SIZE);

		buf->b_paddr = dmac.dmac_address;
//		cmn_err(CE_NOTE, "alloc buf[%d] b_buf = 0x%p b_paddr=0x%x",
//			i, buf->b_buf, buf->b_paddr);
//		sc->sc_vq[0].vq_entries[i].qe_desc->addr = dmac.dmac_address;
	}

	for (i = 0 ; i < txqsize; i++) {
		buf = &sc->sc_txbufs[i];

		if (ddi_dma_alloc_handle(sc->sc_dev, &virtio_net_buf_dma_attr,
			DDI_DMA_SLEEP, NULL, &buf->b_dmah)) {
			
			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate dma handle for tx buffer %d", i);
			goto exit;
		}

		if (ddi_dma_mem_alloc(buf->b_dmah, VIOIF_TX_SIZE,
			&virtio_net_bufattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &buf->b_buf, &len, &buf->b_acch)) {


			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate tx buffer %d", i);
			goto exit;
		}

		if (ddi_dma_addr_bind_handle(buf->b_dmah, NULL, buf->b_buf,
			len, DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
			NULL, &dmac, &nsegments)) {
			
			dev_err(sc->sc_dev, CE_WARN, "Can't bind tx buffer %d", i);

			goto exit;
		}

		/* We asked for a single segment */
		ASSERT(segments == 1);
		ASSERT(len >= VIOIF_TX_SIZE);

		buf->b_paddr = dmac.dmac_address;

//		sc->sc_vq[1].vq_entries[i].qe_desc->addr = dmac.dmac_address;
	}

	return (0);

exit:
	for (i = 0; i < txqsize; i++) {
		buf = &sc->sc_txbufs[i];

		if (buf->b_paddr) {
			ddi_dma_unbind_handle(buf->b_dmah);
		}

		if (buf->b_acch) {
			ddi_dma_mem_free(&buf->b_acch);
		}

		if (buf->b_dmah) {
			ddi_dma_free_handle(&buf->b_dmah);
		}
	}

	for (i = 0; i < rxqsize; i++) {
		buf = &sc->sc_rxbufs[i];

		if (buf->b_paddr) {
			ddi_dma_unbind_handle(buf->b_dmah);
		}

		if (buf->b_acch) {
			ddi_dma_mem_free(&buf->b_acch);
		}

		if (buf->b_dmah) {
			ddi_dma_free_handle(&buf->b_dmah);
		}
	}
exit_alloc:
	if (sc->sc_rxbufs)
		kmem_free(sc->sc_rxbufs, sizeof(struct vioif_buf) * rxqsize);

	if (sc->sc_txbufs)
		kmem_free(sc->sc_txbufs, sizeof(struct vioif_buf) * txqsize);

	return (r);
}

/*
 * 
 */
static int
virtio_net_alloc_mems(struct vioif_softc *sc)
{
/*
	struct virtio_softc *vsc = &sc->sc_virtio;
	int allocsize, allocsize2, r, rsegs, i;
	void *vaddr;
	size_t len;
	unsigned int ncookies;
	intptr_t p;
	int rxqsize, txqsize;
*/
	int r;

//	TRACE;

//	rxqsize = sc->sc_vq[0].vq_num;
//	txqsize = sc->sc_vq[1].vq_num;

	r = virtio_net_alloc_buffers(sc);
	if (r)
		goto exit;

	return (0);
exit:
	return (r);


}

int
virtio_net_quiesce(dev_info_t *dip)
{
	TRACE;
	return DDI_FAILURE;
#if 0

	afe_t	*afep;

	if ((afep = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	SETBIT(afep, CSR_PAR, PAR_RESET);
	/*
	 * At 66 MHz it is 16 nsec per access or more (always more)
	 * So we need 3,333 times to retry for 50 usec.  We just
	 * round up to 5000 times.  Unless the hardware is horked,
	 * it will always terminate *well* before that anyway.
	 */
	for (int i = 0; i < 5000; i++) {
		if ((GETCSR(afep, CSR_PAR) & PAR_RESET) == 0) {
			return (DDI_SUCCESS);
		}
	}

	/* hardware didn't quiesce - force a full reboot (PCI reset) */
	return (DDI_FAILURE);
#endif
}

int
virtio_net_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	TRACE;
	return DDI_FAILURE;

#if 0
	afe_t		*afep = arg;
	int		index;
	uint32_t	crc;
	uint32_t	bit;
	uint32_t	newval, oldval;

	CRC32(crc, macaddr, ETHERADDRL, -1U, crc32_table);
	crc %= AFE_MCHASH;

	/* bit within a 32-bit word */
	index = crc / 32;
	bit = (1 << (crc % 32));

	mutex_enter(&afep->afe_intrlock);
	mutex_enter(&afep->afe_xmtlock);
	newval = oldval = afep->afe_mctab[index];

	if (add) {
		afep->afe_mccount[crc]++;
		if (afep->afe_mccount[crc] == 1)
			newval |= bit;
	} else {
		afep->afe_mccount[crc]--;
		if (afep->afe_mccount[crc] == 0)
			newval &= ~bit;
	}
	if (newval != oldval) {
		afep->afe_mctab[index] = newval;
		afe_setrxfilt(afep);
	}

	mutex_exit(&afep->afe_xmtlock);
	mutex_exit(&afep->afe_intrlock);

	return (0);
#endif
}

int
virtio_net_promisc(void *arg, boolean_t on)
{
	TRACE;
	return DDI_SUCCESS;
#if 0
	afe_t		*afep = arg;

	/* exclusive access to the card while we reprogram it */
	mutex_enter(&afep->afe_intrlock);
	mutex_enter(&afep->afe_xmtlock);
	/* save current promiscuous mode state for replay in resume */
	afep->afe_promisc = on;

	afe_setrxfilt(afep);
	mutex_exit(&afep->afe_xmtlock);
	mutex_exit(&afep->afe_intrlock);

	return (0);
#endif
}

int
virtio_net_unicst(void *arg, const uint8_t *macaddr)
{
	TRACE;
	return DDI_FAILURE;
#if 0
	afe_t		*afep = arg;

	/* exclusive access to the card while we reprogram it */
	mutex_enter(&afep->afe_intrlock);
	mutex_enter(&afep->afe_xmtlock);

	bcopy(macaddr, afep->afe_curraddr, ETHERADDRL);
	afe_setrxfilt(afep);

	mutex_exit(&afep->afe_xmtlock);
	mutex_exit(&afep->afe_intrlock);

	return (0);
#endif
}


static int vioif_populate_rx(struct vioif_softc *sc)
{
	struct virtqueue *vq = &sc->sc_vq[0]; /* rx vq */

	struct vq_entry *ve;
	struct vq_entry *ve_hdr;

	struct vioif_buf *buf;
	struct vioif_buf *buf_hdr;
	struct vring_desc *vd;
	struct vring_desc *vd_hdr;

	struct virtio_net_hdr *hdr;

	int i = 0;

	for (;;) {
		ve_hdr = vq_alloc_entry(vq);
		if (!ve_hdr) {
//			TRACE;
			/* Out of free descriptors - ring already full. */
			return i;
		}
		ve = vq_alloc_entry(vq);
		if (!ve) {
//			TRACE;
			vq_free_entry(vq, ve_hdr);
			/* Out of free descriptors - ring already full. */
			return i;
		}

		buf_hdr = &sc->sc_rxbufs[ve_hdr->qe_index];
		buf = &sc->sc_rxbufs[ve->qe_index];
//		cmn_err(CE_NOTE, "rx push hdr idx: %d, buf idx: %d",
//			ve_hdr->qe_index, ve->qe_index);

//		memset(buf_hdr->b_buf, 0, sizeof(struct virtio_net_hdr));
//		ddi_dma_sync(buf_hdr->b_dmah, 0, sizeof(struct virtio_net_hdr),
//			DDI_DMA_SYNC_FORDEV);

//		memset(buf_hdr->b_buf, 0xa5, sizeof(struct virtio_net_hdr));
//		memset(buf->b_buf, 0xb6, VIOIF_RX_SIZE);

		virtio_ve_set(ve_hdr, buf_hdr->b_dmah, buf_hdr->b_paddr,
			sizeof(struct virtio_net_hdr), B_FALSE);

//		mcopymsg(mb, buf->b_buf);
//		ddi_dma_sync(buf->b_dmah, 0, msg_size, DDI_DMA_SYNC_FORDEV);
		virtio_ve_set(ve, buf->b_dmah, buf->b_paddr,
			VIOIF_RX_SIZE, B_FALSE);


	//	ddi_dma_sync(buf_hdr->b_dmah, 0, sizeof(struct virtio_net_hdr),
	//		DDI_DMA_SYNC_FORDEV);

		ve_hdr->qe_next = ve;
//		cmn_err(CE_NOTE, "push buf[%d] b_buf = 0x%p b_paddr=0x%x",
//			ve_hdr->qe_index, buf_hdr->b_buf, buf_hdr->b_paddr);
//		cmn_err(CE_NOTE, "push buf[%d] b_buf = 0x%p b_paddr=0x%x",
//			ve->qe_index, buf->b_buf, buf->b_paddr);

	//	TRACE;
		vitio_push_chain(vq, ve_hdr);
		i++;
	}

	/* Unreachable */
	return -1;
}

static int vioif_process_rx(struct vioif_softc *sc)
{
	struct virtqueue *vq = &sc->sc_vq[0]; /* rx vq */

	struct vq_entry *ve;
	struct vq_entry *ve_hdr;

	struct vioif_buf *buf;
	struct vioif_buf *buf_hdr;
	struct vring_desc *vd;
	struct vring_desc *vd_hdr;

	struct virtio_net_hdr *hdr;
	mblk_t *mp;

	size_t len;

	int i = 0;
//	TRACE;

	while ((ve_hdr = virtio_pull_chain(vq, &len))) {
//		TRACE;

		ASSERT(ve_hdr->qe_next);
		ve = ve_hdr->qe_next;

		buf_hdr = &sc->sc_rxbufs[ve_hdr->qe_index];
		buf = &sc->sc_rxbufs[ve->qe_index];

		len -= sizeof(struct virtio_net_hdr);

		mp = allocb(len, 0);
		if (!mp) {
			cmn_err(CE_WARN, "Failed to allocale mblock!");
			virtio_free_chain(vq, ve_hdr);
			break;
		}

//		cmn_err(CE_NOTE, "pull hdr buf[%d] b_buf = 0x%p b_paddr=0x%x",
//			ve_hdr->qe_index, buf_hdr->b_buf, buf_hdr->b_paddr);
//		cmn_err(CE_NOTE, "pull pkt buf[%d] b_buf = 0x%p b_paddr=0x%x",
//			ve->qe_index, buf->b_buf, buf->b_paddr);

		ddi_dma_sync(buf->b_dmah, 0, 1514, DDI_DMA_SYNC_FORCPU);
		ddi_dma_sync(buf_hdr->b_dmah, 0, sizeof(struct virtio_net_hdr),
				DDI_DMA_SYNC_FORCPU);

//		hex_dump("hdr", buf_hdr->b_buf, sizeof(struct virtio_net_hdr));
//		hex_dump("rx", buf->b_buf, len);

		bcopy((char *)buf->b_buf, mp->b_rptr, len);
//		cmn_err(CE_NOTE, "mbuf: rptr: %p, wptr: %p",
//				mp->b_rptr, mp->b_wptr);

		mp->b_wptr = mp->b_rptr + len;

		virtio_free_chain(vq, ve_hdr);

		mac_rx(sc->sc_mac_handle, NULL, mp);
		
//		cmn_err(CE_NOTE, "Pushed mblock (len = %ld) to mac", len);
		i++;
	}

	return i;
}

static void vioif_reclaim_used_tx(struct vioif_softc *sc)
{
	struct virtqueue *vq = &sc->sc_vq[1];
	struct vq_entry *ve;

	size_t len;

//	TRACE;

	mutex_enter(&sc->sc_tx_lock);
	while ((ve = virtio_pull_chain(vq, &len))) {
//		TRACE;
		virtio_free_chain(vq, ve);
		if (sc->sc_stopped) {
			sc->sc_stopped = 0;
			mac_tx_update(sc->sc_mac_handle);
		}
	}
	mutex_exit(&sc->sc_tx_lock);
}


/*
 * Interrupt service routine.
 */
unsigned int
vioif_intr(caddr_t arg)
{
	uint8_t isr_status;
	struct vioif_softc *sc = (void *)arg;
	int i;

	isr_status = ddi_get8(sc->sc_virtio.sc_ioh,
		(uint8_t *) (sc->sc_virtio.sc_io_addr + VIRTIO_CONFIG_ISR_STATUS));

//	cmn_err(CE_NOTE, "Isr! status = %x\n", isr_status);

	if (!isr_status)
		return DDI_INTR_UNCLAIMED;

	
	vioif_reclaim_used_tx(sc);
	i = vioif_process_rx(sc);
//	if (i) {
//		cmn_err(CE_NOTE, "Pushed %d blocks to mac", i);
//	}
	i = vioif_populate_rx(sc);
//	if (i) {
//		cmn_err(CE_NOTE, "Pushed %d rx descriptors", i);
//	}

	return DDI_INTR_CLAIMED;
}
static bool
virtio_net_send(struct vioif_softc *sc, mblk_t *mb)
{
//	struct vioif_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = &sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[1]; /* tx vq */
	struct vq_entry *ve;
	struct vq_entry *ve_hdr;
	struct vring_desc *vd;
	struct vring_desc *vd_hdr;
	mblk_t *m;

	int i;

	struct vioif_buf *buf;
	struct vioif_buf *buf_hdr;
	struct virtio_net_hdr *hdr;
	int nsegments = 0;
	size_t msg_size = 0;

	static int once = 0;

//	int queued = 0, retry = 0;
//	struct vq_entry *hdr_ve;
//	struct virtio_net_hdr *hdr;

//	TRACE;

//	cmn_err(CE_NOTE, "once = %d", once);

//	if (once++ > 1) {
//		TRACE;
//		return (B_FALSE);
//	}


	msg_size = msgsize(mb);
	if (msg_size > ETHERVLANMTU) {
		dev_err(sc->sc_dev, CE_WARN, "Message too big");
		freemsg(mb);
		return (B_TRUE);
	}

//	cmn_err(CE_NOTE, "msg_size = %ld", msg_size);

	ve_hdr = vq_alloc_entry(vq);
	if (!ve_hdr) {
//		TRACE;
		/* Out of free descriptors - try later.*/
		return (B_FALSE);
	}
	ve = vq_alloc_entry(vq);
	if (!ve) {
//		TRACE;
		vq_free_entry(vq, ve_hdr);
		/* Out of free descriptors - try later.*/
		return (B_FALSE);
	}

	buf_hdr = &sc->sc_txbufs[ve_hdr->qe_index];
	buf = &sc->sc_txbufs[ve->qe_index];
//	cmn_err(CE_NOTE, "hdr idx: %d, buf idx: %d", ve_hdr->qe_index, ve->qe_index);

	memset(buf_hdr->b_buf, 0, sizeof(struct virtio_net_hdr));
	ddi_dma_sync(buf_hdr->b_dmah, 0, sizeof(struct virtio_net_hdr),
		DDI_DMA_SYNC_FORDEV);

	virtio_ve_set(ve_hdr, buf_hdr->b_dmah, buf_hdr->b_paddr,
		sizeof(struct virtio_net_hdr), B_TRUE);

	mcopymsg(mb, buf->b_buf);
	ddi_dma_sync(buf->b_dmah, 0, msg_size, DDI_DMA_SYNC_FORDEV);
	virtio_ve_set(ve, buf->b_dmah, buf->b_paddr, msg_size, B_TRUE);


//	ddi_dma_sync(buf_hdr->b_dmah, 0, sizeof(struct virtio_net_hdr),
//		DDI_DMA_SYNC_FORDEV);

	ve_hdr->qe_next = ve;

//	TRACE;
	vitio_push_chain(vq, ve_hdr);
//	TRACE;

#if 0
	mutex_enter(&vq->vq_aring_lock);

	cmn_err(CE_NOTE, "vq->vq_avail_idx = %d\n", vq->vq_avail_idx);

	vq->vq_avail->ring[(vq->vq_avail_idx++) % vq->vq_num] = ve_hdr->qe_index;
	vq->vq_avail->ring[(vq->vq_avail_idx++) % vq->vq_num] = ve->qe_index;

	ddi_dma_sync(vq->vq_dma_handle,
		vq->vq_availoffset,
		sizeof(struct vring_avail) + sizeof(uint16_t) * vq->vq_num,
		DDI_DMA_SYNC_FORDEV);

	vq->vq_avail->idx = vq->vq_avail_idx;
	vq->vq_avail->flags = /*VRING_AVAIL_F_NO_INTERRUPT*/ 0;
/*
	ddi_dma_sync(vq->vq_dma_handle,
		vq->vq_availoffset,
		sizeof(struct vring_avail) + sizeof(uint16_t) * vq->vq_num,
		DDI_DMA_SYNC_FORDEV);


	ddi_dma_sync(vq->vq_dma_handle, sizeof(struct vring_desc) * ve->qe_index,
			sizeof(struct vring_desc), DDI_DMA_SYNC_FORDEV);
*/
	ddi_dma_sync(vq->vq_dma_handle, 0,
			0x4000, DDI_DMA_SYNC_FORDEV);
	cmn_err(CE_NOTE, "idx = %d", vq->vq_avail->idx);
	cmn_err(CE_NOTE, "vq->vq_used->flags = %x", vq->vq_used->flags);

	mutex_exit(&vq->vq_aring_lock);

	ddi_put16(vsc->sc_ioh,
		(uint16_t *) (vsc->sc_io_addr + VIRTIO_CONFIG_QUEUE_NOTIFY),
		vq->vq_index);
#endif
	return (B_TRUE);
}

mblk_t *
virtio_net_tx(void *arg, mblk_t *mp)
{
	struct vioif_softc *sc = arg;
	mblk_t	*nmp;

//	TRACE;
	mutex_enter(&sc->sc_tx_lock);

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!virtio_net_send(sc, mp)) {
			cmn_err(CE_NOTE, "##");
			sc->sc_stopped = 1;
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}
	mutex_exit(&sc->sc_tx_lock);

	return (mp);
}

int
virtio_net_start(void *arg)
{
	struct vioif_softc *sc = arg;

	TRACE;

	mac_link_update(sc->sc_mac_handle,
		virtio_net_link_state(sc));

	vioif_populate_rx(sc);

	return (DDI_SUCCESS);
}

void
virtio_net_stop(void *arg)
{
	struct vioif_softc *sc = arg;
	TRACE;
	
}


static int
virtio_net_stat(void *arg, uint_t stat, uint64_t *val)
{
//	TRACE;
	cmn_err(CE_NOTE, "stat = %x\n", stat);
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

	cmn_err(CE_NOTE, "val = %lu\n", *val);

	return (DDI_SUCCESS);
}



static mac_callbacks_t afe_m_callbacks = {
	/*MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO*/ 0,
	virtio_net_stat,
	virtio_net_start,
	virtio_net_stop,
	virtio_net_promisc,
	virtio_net_multicst,
	virtio_net_unicst,
	virtio_net_tx,
	NULL,
	/*afe_m_ioctl*/ NULL,	/* mc_ioctl */
	NULL,		/* mc_getcapab */
	NULL,		/* mc_open */
	NULL,		/* mc_close */
	NULL, /* afe_m_setprop */
	NULL, /* afe_m_getprop */
	NULL, /* afe_m_propinfo */
};

static int
virtio_net_match(dev_info_t *devinfo, ddi_acc_handle_t pconf)
{
	uint16_t vendor, device, revision, subdevice, subvendor;

	vendor = pci_config_get16(pconf, PCI_CONF_VENID);
	device = pci_config_get16(pconf, PCI_CONF_DEVID);
	revision = pci_config_get8(pconf, PCI_CONF_REVID);
	subvendor = pci_config_get16(pconf, PCI_CONF_SUBVENID);
	subdevice = pci_config_get16(pconf, PCI_CONF_SUBSYSID);

	dev_err(devinfo, CE_NOTE, "match: %x:%x, rev %d, sub: %x:%x",
		vendor, device, revision, subvendor, subdevice);

	if (vendor != PCI_VENDOR_QUMRANET) {
		dev_err(devinfo, CE_WARN,
			"Vendor ID does not match: %x, expected %x",
			vendor, PCI_VENDOR_QUMRANET);
		return (DDI_FAILURE);
	}

	if (device < PCI_DEV_VIRTIO_MIN || device > PCI_DEV_VIRTIO_MAX) {
		dev_err(devinfo, CE_WARN,
			"Device ID is does not match: %x, expected"
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

	dev_err(devinfo, CE_NOTE, "Matched successfully");

	return (DDI_SUCCESS);
}

static void
virtio_net_show_features(struct vioif_softc *sc, uint32_t features)
{
	virtio_show_features(&sc->sc_virtio, features);

	dev_err(sc->sc_dev, CE_NOTE, "Virtio Net features:");

	if (features & VIRTIO_NET_F_CSUM)
		dev_err(sc->sc_dev, CE_NOTE, "CSUM");
	if (features & VIRTIO_NET_F_GUEST_CSUM)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_CSUM");
	if (features & VIRTIO_NET_F_MAC)
		dev_err(sc->sc_dev, CE_NOTE, "MAC");
	if (features & VIRTIO_NET_F_GSO)
		dev_err(sc->sc_dev, CE_NOTE, "GSO");
	if (features & VIRTIO_NET_F_GUEST_TSO4)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_TSO4");
	if (features & VIRTIO_NET_F_GUEST_TSO6)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_TSO6");
	if (features & VIRTIO_NET_F_GUEST_ECN)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_ECN");
	if (features & VIRTIO_NET_F_GUEST_UFO)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_UFO");
	if (features & VIRTIO_NET_F_HOST_TSO4)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_TSO4");
	if (features & VIRTIO_NET_F_HOST_TSO6)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_TSO6");
	if (features & VIRTIO_NET_F_HOST_ECN)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_ECN");
	if (features & VIRTIO_NET_F_HOST_UFO)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_UFO");
	if (features & VIRTIO_NET_F_MRG_RXBUF)
		dev_err(sc->sc_dev, CE_NOTE, "MRG_RXBUF");
	if (features & VIRTIO_NET_F_STATUS)
		dev_err(sc->sc_dev, CE_NOTE, "STATUS");
	if (features & VIRTIO_NET_F_CTRL_VQ)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_VQ");
	if (features & VIRTIO_NET_F_CTRL_RX)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_RX");
	if (features & VIRTIO_NET_F_CTRL_VLAN)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_VLAN");
	if (features & VIRTIO_NET_F_CTRL_RX_EXTRA)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_RX_EXTRA");
}

/*
 * Find out which features are supported by the device and
 * chose which ones we wish to use.
 */
static int
virtio_net_dev_features(struct vioif_softc *sc)
{
	uint32_t host_features;


	host_features = virtio_negotiate_features(&sc->sc_virtio,
			VIRTIO_NET_F_CSUM |
			VIRTIO_NET_F_MAC |
			VIRTIO_NET_F_STATUS |
//			VIRTIO_NET_F_CTRL_VQ |
//			VIRTIO_NET_F_CTRL_RX |
			VIRTIO_F_NOTIFY_ON_EMPTY /*|
			VRING_DESC_F_INDIRECT*/);

#if 0
	if (!(sc->sc.features & VIRTIO_RING_F_INDIRECT_DESC)) {
		dev_err(sc->sc_dev, CE_WARN,
			"Virtual device does not support indirect descriptors - host too old");
		return (DDI_FAILURE);
	}
#endif
	dev_err(sc->sc_dev, CE_NOTE, "Host features:");
	virtio_net_show_features(sc, host_features);

	dev_err(sc->sc_dev, CE_NOTE, "Negotiated features:");
	virtio_net_show_features(sc, sc->sc_virtio.sc_features);

	return (DDI_SUCCESS);
}

static void
virtio_net_set_mac(struct vioif_softc *sc)
{
	int i;

	for (i = 0; i < ETHERADDRL; i++) {
		virtio_write_device_config_1(&sc->sc_virtio,
			VIRTIO_NET_CONFIG_MAC + i, sc->sc_mac[i]);
	}
}

/* Get the mac address out of the hardware, or make up one. */
static void
virtio_net_get_mac(struct vioif_softc *sc)
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

		virtio_net_set_mac(sc);

		dev_err(sc->sc_dev, CE_NOTE, "Generated a random Got MAC address: %s",
			ether_sprintf((struct ether_addr *) sc->sc_mac));
	}
	
}

/*
 * virtio_net_attach
 * @devinfo: pointer to dev_info_t structure
 * @cmd: attach command to process
 */
static int
virtio_net_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int ret, instance, intr_types;
	struct vioif_softc *sc;
	struct virtio_softc *vsc;
	mac_register_t *macp;
	ddi_acc_handle_t pci_conf;
	struct vioif_buf *buf;
	TRACE;


	instance = ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		dev_err(devinfo, CE_WARN, "resume unsupported yet");
		ret = DDI_FAILURE;
		goto exit;

	default:
		dev_err(devinfo, CE_WARN, "cmd 0x%x unrecognized", cmd);
		ret = DDI_FAILURE;
		goto exit;
	}

	sc = kmem_zalloc(sizeof (struct vioif_softc), KM_SLEEP);
	ddi_set_driver_private(devinfo, sc);

	vsc = &sc->sc_virtio;
	/* Duplicate for faster access / less typing */
	sc->sc_dev = devinfo;
	vsc->sc_dev = devinfo;

	ret = pci_config_setup(devinfo, &pci_conf);
	if (ret) {
		dev_err(devinfo, CE_WARN, "unable to setup PCI config handle");
		goto exit_pci_conf;

	}

	ret = virtio_net_match(devinfo, pci_conf);
	if (ret)
		goto exit_match;

//	/* get the interrupt block cookie */
//	if (ddi_get_iblock_cookie(devinfo, 0, &sc->sc_icookie) != DDI_SUCCESS) {
//		dev_err(devinfo, CE_WARN,"ddi_get_iblock_cookie failed");
//		goto exit_int_prio;
//	}
/* PCI configuration registers */
#define PCI_VID         0x00    /* Loaded vendor ID */
#define PCI_DID         0x02    /* Loaded device ID */
#define PCI_CMD         0x04    /* Configuration command register */
#define PCI_STAT        0x06    /* Configuration status register */
#define PCI_RID         0x08    /* Revision ID */
#define PCI_CLS         0x0c    /* Cache line size */
#define PCI_SVID        0x2c    /* Subsystem vendor ID */
#define PCI_SSID        0x2e    /* Subsystem ID */
#define PCI_MINGNT      0x3e    /* Minimum Grant */
#define PCI_MAXLAT      0x3f    /* Maximum latency */
#define PCI_SIG         0x80    /* Signature of AN983 */ 
#define PCI_PMR0        0xc0    /* Power Management Register 0 */
#define PCI_PMR1        0xc4    /* Power Management Register 1 */

/*
 * Bits for PCI command register.
 */
#define PCI_CMD_MWIE    0x0010  /* memory write-invalidate enable */
#define PCI_CMD_BME     0x0004  /* bus master enable */
#define PCI_CMD_MAE     0x0002  /* memory access enable */
#define PCI_CMD_IOE     0x0001  /* I/O access enable */


         /*
         * Enable bus master, IO space, and memory space accesses.
         */
//        pci_config_put16(pci_conf, PCI_CMD,
  //          pci_config_get16(pci_conf, PCI_CMD) | PCI_CMD_BME | PCI_CMD_MAE); 

//	pci_config_teardown(&pci_conf);

	/* Determine which types of interrupts supported */
	ret = ddi_intr_get_supported_types(devinfo, &intr_types);
	if ((ret != DDI_SUCCESS) || (!(intr_types & DDI_INTR_TYPE_FIXED))) {
		dev_err(devinfo, CE_WARN, "fixed type interrupt is not supported");
		goto exit_inttype;
	}

        if (ddi_get_iblock_cookie(devinfo, 0, &vsc->sc_icookie)) {
                dev_err(devinfo, CE_WARN, "ddi_get_iblock_cookie failed");

		goto exit_cookie;
        }


	/*
	 * Initialize interrupt kstat.  This should not normally fail, since
	 * we don't use a persistent stat.  We do it this way to avoid having
	 * to test for it at run time on the hot path.
	 */
	sc->sc_intrstat = kstat_create("virtio_net", instance, "intr", "controller",
		KSTAT_TYPE_INTR, 1, 0);
	if (sc->sc_intrstat == NULL) {
		dev_err(devinfo, CE_WARN, "kstat_create failed");
		goto exit_intrstat;
	}
	kstat_install(sc->sc_intrstat);


	/* map BAR0 */
	ret = ddi_regs_map_setup(devinfo, 1, (caddr_t *)&sc->sc_virtio.sc_io_addr,
		0, 0, &virtio_net_attr, &sc->sc_virtio.sc_ioh);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "unable to map bar0: [%d]", ret);
		goto exit_map;
	}

	sc->sc_virtio.sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;

	virtio_reset(&sc->sc_virtio);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	ret = virtio_net_dev_features(sc);
	if (ret)
		goto exit_features;

	virtio_net_get_mac(sc);

	ret = virtio_alloc_vq(&sc->sc_virtio, &sc->sc_vq[0], 0, VIOIF_RX_QLEN, "rx");
	if (ret) {
		goto exit_alloc1;
	}

	sc->sc_nvqs = 1;
//	sc->sc_virtio_vq[0].vq_done = vioif_rx_vq_done;
	ret = virtio_alloc_vq(&sc->sc_virtio, &sc->sc_vq[1], 1, VIOIF_TX_QLEN, "tx");
	if (ret) {
		goto exit_alloc2;
	}

	sc->sc_nvqs = 2;
//	sc->sc_virtio_vq[1].vq_done = vioif_tx_vq_done;
//	virtio_start_vq_intr(&sc->sc_vq[0]);
//	virtio_stop_vq_intr(&sc->sc_vq[1]); /* not urgent; do it later */
/*
	if ((features & VIRTIO_NET_F_CTRL_VQ)
	    && (features & VIRTIO_NET_F_CTRL_RX)) {
		if (virtio_alloc_vq(vsc, &sc->sc_vq[2], 2,
				    NBPG, 1, "control") == 0) {
			sc->sc_virtio_vq[2].vq_done = vioif_ctrl_vq_done;
			cv_init(&sc->sc_virtio_ctrl_wait, "ctrl_vq");
			mutex_init(&sc->sc_virtio_ctrl_wait_lock,
				   MUTEX_DEFAULT, IPL_NET);
			sc->sc_virtio_ctrl_inuse = FREE;
			virtio_start_vq_intr(vsc, &sc->sc_virtio_vq[2]);
			vsc->sc_virtio_nvqs = 3;
		}
	}
*/

	cmn_err(CE_NOTE, "vq[0].vq_num = %d, vq[1].vq_num = %d",
			sc->sc_vq[0].vq_num, sc->sc_vq[1].vq_num);
	if (virtio_net_alloc_mems(sc))
		goto exit_alloc_mems;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		dev_err(devinfo, CE_WARN, "Failed to alocate a mac_register");
		goto exit_macalloc;
	}

	/*
	* Establish interrupt handler.
	*/
	if (ddi_add_intr(devinfo, 0, NULL, NULL,
			vioif_intr, (caddr_t)sc)) {
		dev_err(devinfo, CE_WARN, "unable to add interrupt");
		goto exit_int;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = sc;
	macp->m_dip = devinfo;
	macp->m_src_addr = sc->sc_mac;
	macp->m_callbacks = &afe_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;
	mutex_init(&sc->sc_tx_lock, "virtio",
			MUTEX_DRIVER, vsc->sc_icookie);



	dev_err(sc->sc_dev, CE_NOTE, "Registering the mac!");
	ret = mac_register(macp, &sc->sc_mac_handle);
	if (ret) {
		dev_err(devinfo, CE_WARN, "Failed to register the device");
		goto exit_register;
	}

	sc->sc_macp = macp;

	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);


	buf = &sc->sc_txbufs[0];
	cmn_err(CE_NOTE, "## buf = %p, buf[0].b_buf = %p", buf, buf->b_buf);
	dev_err(sc->sc_dev, CE_NOTE, "Attach done!");

	return (DDI_SUCCESS);

exit_register:
	ddi_remove_intr(devinfo, 0, vsc->sc_icookie);
exit_int:
	mac_free(macp);
exit_macalloc:
//	virtio_net_free_mems(sc);
exit_alloc_mems:
	virtio_free_vq(&sc->sc_virtio, &sc->sc_vq[1]);
exit_alloc2:
	virtio_free_vq(&sc->sc_virtio, &sc->sc_vq[0]);
exit_alloc1:
exit_features:
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_FAILED);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
exit_intrstat:
exit_map:
	kstat_delete(sc->sc_intrstat);
exit_inttype:
exit_cookie:
//exit_int_prio:
exit_match:
exit_pci_conf:
	kmem_free(sc, sizeof (struct vioif_softc));
exit:
	return (ret);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
#if 0
static int
virtio_net_quiesce(dev_info_t *devinfo)
{
	struct vioif_softc *dp = ddi_get_driver_private(devinfo);
	TRACE;

	/* FIXME: not implemented */

	return (DDI_FAILURE);
}
#endif


/*
 * virtio_net_detach
 * @devinfo: pointer to dev_info_t structure
 * @cmd: attach command to process
 */
static int
virtio_net_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct vioif_softc *sc = ddi_get_driver_private(devinfo);

//	TRACE;
	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_PM_SUSPEND:
		cmn_err(CE_WARN, "suspend unsupported yet");
		return (DDI_FAILURE);

	default:
		cmn_err(CE_WARN, "cmd 0x%x unrecognized", cmd);
		return (DDI_FAILURE);
	}

	if (mac_unregister(sc->sc_mac_handle)) {
		return (DDI_FAILURE);
	}

	mac_free(sc->sc_macp);
	ddi_remove_intr(devinfo, 0, sc->sc_virtio.sc_icookie);
	virtio_free_vq(&sc->sc_virtio, &sc->sc_vq[0]);
	virtio_free_vq(&sc->sc_virtio, &sc->sc_vq[1]);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
	kstat_delete(sc->sc_intrstat);
//	pci_config_teardown(&sc->sc_virtio.pci_conf);
	kmem_free(sc, sizeof (struct vioif_softc));

	return (DDI_SUCCESS);
}
