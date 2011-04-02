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
#include <sys/vlan.h>
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
	MODREV_1, (void *)&modldrv, NULL
};

ddi_device_acc_attr_t virtio_net_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
struct vioif_softc {
	struct virtio_softc sc;
	mac_handle_t mac_handle;
	uint8_t mac_address[ETHERADDRL];
};
*/

struct mbuf_desc {
	ddi_dma_cookie_t	md_dma_cookie;
	ddi_dma_handle_t	md_dma_handle;
	ddi_acc_handle_t	md_dma_acch;
	struct mbuf		*md_mbuf;
};

struct vioif_softc {
	dev_info_t		*sc_dev; /* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;

	mac_handle_t sc_mac_handle;
	mac_register_t *sc_macp;

	int			sc_nvqs; /* set by the user */ 
	struct virtqueue	sc_vq[3];

	uint8_t			sc_mac[ETHERADDRL];
//	struct ethercom		sc_ethercom;
//	uint32_t		sc_features;
	short			sc_ifflags;

	ddi_dma_cookie_t	sc_hdr_dma_cookie;
	ddi_dma_handle_t	sc_hdr_dma_handle;
	ddi_acc_handle_t	sc_hdr_dma_acch;
	/* bus_dmamem */
//	bus_dma_segment_t	sc_hdr_segs[1];
	struct virtio_net_hdr	*sc_rx_hdrs;
//#define sc_rx_hdrs	sc_hdrs
	struct virtio_net_hdr	*sc_tx_hdrs;

	struct mbuf_desc	*sc_rx_mbuf_descs;
	struct mbuf_desc	*sc_tx_mbuf_descs;
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
};
#define VIRTIO_NET_TX_MAXNSEGS		(16) /* XXX */
#define VIRTIO_NET_CTRL_MAC_MAXENTRIES	(64) /* XXX */
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
	uint16_t tmp;

	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_STATUS) {
		if (virtio_read_device_config_2(&sc->sc_virtio,
			VIRTIO_NET_CONFIG_STATUS) & VIRTIO_NET_S_LINK_UP) {
			return (LINK_STATE_UP);
		} else {
			return (LINK_STATE_DOWN);
		}
	}

	return (LINK_STATE_UP);

}

static ddi_dma_attr_t virtio_net_hdr_dma_attr = {
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

static ddi_device_acc_attr_t virtio_net_hdr_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/* allocate memory */
/*
 * dma memory is used for:
 *   sc_rx_hdrs[slot]:	 metadata array for recieved frames (READ)
 *   sc_tx_hdrs[slot]:	 metadata array for frames to be sent (WRITE)
 *   sc_ctrl_cmd:	 command to be sent via ctrl vq (WRITE)
 *   sc_ctrl_status:	 return value for a command via ctrl vq (READ)
 *   sc_ctrl_rx:	 parameter for a VIRTIO_NET_CTRL_RX class command
 *			 (WRITE)
 *   sc_ctrl_mac_tbl_uc: unicast MAC address filter for a VIRTIO_NET_CTRL_MAC
 *			 class command (WRITE)
 *   sc_ctrl_mac_tbl_mc: multicast MAC address filter for a VIRTIO_NET_CTRL_MAC
 *			 class command (WRITE)
 * sc_ctrl_* structures are allocated only one each; they are protected by
 * sc_ctrl_inuse variable and sc_ctrl_wait condvar.
 */
/*
 * dynamically allocated memory is used for:
 *   sc_rxhdr_dmamaps[slot]:	bus_dmamap_t array for sc_rx_hdrs[slot]
 *   sc_txhdr_dmamaps[slot]:	bus_dmamap_t array for sc_tx_hdrs[slot]
 *   sc_rx_dmamaps[slot]:	bus_dmamap_t array for recieved payload
 *   sc_tx_dmamaps[slot]:	bus_dmamap_t array for sent payload
 *   sc_rx_mbufs[slot]:		mbuf pointer array for recieved frames
 *   sc_tx_mbufs[slot]:		mbuf pointer array for sent frames
 */
static int
virtio_net_alloc_mems(struct vioif_softc *sc)
{
	struct virtio_softc *vsc = &sc->sc_virtio;
	int allocsize, allocsize2, r, rsegs, i;
	void *vaddr;
	size_t len;
	unsigned int ncookies;
	intptr_t p;
	int rxqsize, txqsize;

	TRACE;

	rxqsize = sc->sc_vq[0].vq_num;
	txqsize = sc->sc_vq[1].vq_num;

	allocsize = sizeof(struct virtio_net_hdr) * rxqsize;
	allocsize += sizeof(struct virtio_net_hdr) * txqsize;
	if (vsc->sc_nvqs == 3) {
		TRACE;
		panic("Not implemented");
#if 0
		allocsize += sizeof(struct virtio_net_ctrl_cmd) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_status) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_rx) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_mac_tbl)
			+ sizeof(struct virtio_net_ctrl_mac_tbl)
			+ ETHERADDRL * VIRTIO_NET_CTRL_MAC_MAXENTRIES;
#endif
	}
	r = ddi_dma_alloc_handle(sc->sc_dev, &virtio_net_hdr_dma_attr,
		DDI_DMA_SLEEP, NULL, &sc->sc_hdr_dma_handle);
	if (r) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to allocate dma handle for data headers");
		goto out;
	}

	r = ddi_dma_mem_alloc(sc->sc_hdr_dma_handle, allocsize, &virtio_net_hdr_devattr,
		DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		(caddr_t *)&sc->sc_rx_hdrs, &len, &sc->sc_hdr_dma_acch);
	if (r) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to alocate dma memory for data headers");
		goto out_mem;
	}

	r = ddi_dma_addr_bind_handle(sc->sc_hdr_dma_handle, NULL,
		(caddr_t) sc->sc_rx_hdrs, allocsize, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		DDI_DMA_SLEEP, NULL, &sc->sc_hdr_dma_cookie, &ncookies);
	if (r != DDI_DMA_MAPPED) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to bind dma memory for data headers");
		goto out_bind;
	}

	/* We asked for a single segment */
	ASSERT(ncookies == 1);
#if 0
	r = bus_dmamem_alloc(vsc->sc_dmat, allocsize, 0, 0,
			     &sc->sc_hdr_segs[0], 1, &rsegs, BUS_DMA_NOWAIT);
	if (r != 0) {
		aprint_error_dev(sc->sc_dev,
				 "DMA memory allocation failed, size %d, "
				 "error code %d\n", allocsize, r);
		goto err_none;
	}
	r = bus_dmamem_map(vsc->sc_dmat,
			   &sc->sc_hdr_segs[0], 1, allocsize,
			   &vaddr, BUS_DMA_NOWAIT);
	if (r != 0) {
		aprint_error_dev(sc->sc_dev,
				 "DMA memory map failed, "
				 "error code %d\n", r);
		goto err_dmamem_alloc;
	}
#endif
//	sc->sc_rx_hdrs = vaddr;
	memset(sc->sc_rx_hdrs, 0, allocsize);
	p = (intptr_t) vaddr;
	p += sizeof(struct virtio_net_hdr) * rxqsize;
#define P(name,size)	do { sc->sc_ ##name = (void*) p;	\
			     p += size; } while (0)
	P(tx_hdrs, sizeof(struct virtio_net_hdr) * txqsize);
	if (vsc->sc_nvqs == 3) {
		TRACE;
		panic("Not implemented");
#if 0
		P(ctrl_cmd, sizeof(struct virtio_net_ctrl_cmd));
		P(ctrl_status, sizeof(struct virtio_net_ctrl_status));
		P(ctrl_rx, sizeof(struct virtio_net_ctrl_rx));
		P(ctrl_mac_tbl_uc, sizeof(struct virtio_net_ctrl_mac_tbl));
		P(ctrl_mac_tbl_mc,
		  (sizeof(struct virtio_net_ctrl_mac_tbl)
		   + ETHER_ADDR_LEN * VIRTIO_NET_CTRL_MAC_MAXENTRIES));
#endif
	}
#undef P

//	allocsize2 = sizeof(bus_dmamap_t) * (rxqsize + txqsize);
//	allocsize2 += sizeof(bus_dmamap_t) * (rxqsize + txqsize);
//	allocsize2 = sizeof(struct mbuf_desc) * (rxqsize + txqsize);
	sc->sc_rx_mbuf_descs =
		kmem_zalloc(sizeof(struct mbuf_desc) * (rxqsize + txqsize),
			KM_SLEEP);

	if (!sc->sc_rx_mbuf_descs)
		goto out_alloc_desc;

	sc->sc_tx_mbuf_descs = sc->sc_rx_mbuf_descs + rxqsize;
/*	
	sc->sc_txhdr_dmamaps = sc->sc_arrays + rxqsize;
	sc->sc_rx_dmamaps = sc->sc_txhdr_dmamaps + txqsize;
	sc->sc_tx_dmamaps = sc->sc_rx_dmamaps + rxqsize;
	sc->sc_rx_mbufs = (void*) (sc->sc_tx_dmamaps + txqsize);
	sc->sc_tx_mbufs = sc->sc_rx_mbufs + rxqsize;
*/

#if 0
#define C(map, buf, size, nsegs, rw, usage)				\
	do {								\
		r = bus_dmamap_create(vsc->sc_dmat, size, nsegs, size, 0, \
				      BUS_DMA_NOWAIT|BUS_DMA_ALLOCNOW,	\
				      &sc->sc_ ##map);			\
		if (r != 0) {						\
			aprint_error_dev(sc->sc_dev,			\
					 usage " dmamap creation failed, " \
					 "error code %d\n", r);		\
					 goto err_reqs;			\
		}							\
	} while (0)
#define C_L1(map, buf, size, nsegs, rw, usage)				\
	C(map, buf, size, nsegs, rw, usage);				\
	do {								\
		r = bus_dmamap_load(vsc->sc_dmat, sc->sc_ ##map,	\
				    &sc->sc_ ##buf, size, NULL,		\
				    BUS_DMA_ ##rw | BUS_DMA_NOWAIT);	\
		if (r != 0) {						\
			aprint_error_dev(sc->sc_dev,			\
					 usage " dmamap load failed, "	\
					 "error code %d\n", r);		\
			goto err_reqs;					\
		}							\
	} while (0)
#define C_L2(map, buf, size, nsegs, rw, usage)				\
	C(map, buf, size, nsegs, rw, usage);				\
	do {								\
		r = bus_dmamap_load(vsc->sc_dmat, sc->sc_ ##map,	\
				    sc->sc_ ##buf, size, NULL,		\
				    BUS_DMA_ ##rw | BUS_DMA_NOWAIT);	\
		if (r != 0) {						\
			aprint_error_dev(sc->sc_dev,			\
					 usage " dmamap load failed, "	\
					 "error code %d\n", r);		\
			goto err_reqs;					\
		}							\
	} while (0)
	for (i = 0; i < rxqsize; i++) {
		C_L1(rxhdr_dmamaps[i], rx_hdrs[i],
		    sizeof(struct virtio_net_hdr), 1,
		    READ, "rx header");
		C(rx_dmamaps[i], NULL, MCLBYTES, 1, 0, "rx payload");
	}

	for (i = 0; i < txqsize; i++) {
		C_L1(txhdr_dmamaps[i], rx_hdrs[i],
		    sizeof(struct virtio_net_hdr), 1,
		    WRITE, "tx header");
		C(tx_dmamaps[i], NULL, ETHER_MAX_LEN, 256 /* XXX */, 0,
		  "tx payload");
	}
#endif

	/* Allocate dma handles for rx and tx segments. */
	for (i = 0; i < rxqsize + txqsize; i++) {
		/* tx desc follow right after th rx descs. */
		r = ddi_dma_alloc_handle(sc->sc_dev, &virtio_net_hdr_dma_attr,
			DDI_DMA_SLEEP, NULL, &sc->sc_rx_mbuf_descs[i].md_dma_handle);
		if (r) {
			dev_err(sc->sc_dev, CE_WARN,
				"Failed to allocate dma handle for data headers");
			goto out_alloc_desc_handle;
		}
#if 0

		C_L1(rxhdr_dmamaps[i], rx_hdrs[i],
		    sizeof(struct virtio_net_hdr), 1,
		    READ, "rx header");
		C(rx_dmamaps[i], NULL, MCLBYTES, 1, 0, "rx payload");
#endif
	}
#if 0
	for (i = 0; i < txqsize; i++) {
		C_L1(txhdr_dmamaps[i], rx_hdrs[i],
		    sizeof(struct virtio_net_hdr), 1,
		    WRITE, "tx header");
		C(tx_dmamaps[i], NULL, ETHER_MAX_LEN, 256 /* XXX */, 0,
		  "tx payload");
	}
#endif
	if (vsc->sc_nvqs == 3) {
		TRACE;

		panic("Not implemented");
#if 0
		/* control vq class & command */
		C_L2(ctrl_cmd_dmamap, ctrl_cmd,
		    sizeof(struct virtio_net_ctrl_cmd), 1, WRITE,
		    "control command");
		
		/* control vq status */
		C_L2(ctrl_status_dmamap, ctrl_status,
		    sizeof(struct virtio_net_ctrl_status), 1, READ,
		    "control status");

		/* control vq rx mode command parameter */
		C_L2(ctrl_rx_dmamap, ctrl_rx,
		    sizeof(struct virtio_net_ctrl_rx), 1, WRITE,
		    "rx mode control command");

		/* control vq MAC filter table for unicast */
		/* do not load now since its length is variable */
		C(ctrl_tbl_uc_dmamap, NULL,
		  sizeof(struct virtio_net_ctrl_mac_tbl) + 0, 1, WRITE,
		  "unicast MAC address filter command");

		/* control vq MAC filter table for multicast */
		C(ctrl_tbl_mc_dmamap, NULL,
		  (sizeof(struct virtio_net_ctrl_mac_tbl)
		   + ETHER_ADDR_LEN * VIRTIO_NET_CTRL_MAC_MAXENTRIES),
		  1, WRITE, "multicast MAC address filter command");
#endif
	}
//#undef C_L2
//#undef C_L1
//#undef C

	return (DDI_SUCCESS);

out_alloc_desc_handle:
	for (i = 0; i < rxqsize + txqsize; i++) {
		if (sc->sc_rx_mbuf_descs[i].md_dma_handle) {
			ddi_dma_free_handle(&sc->sc_hdr_dma_handle);
		} else {
			break;
		}
	}

	kmem_free(sc->sc_rx_mbuf_descs,
		sizeof(struct mbuf_desc) * (rxqsize + txqsize));

out_alloc_desc:
	ddi_dma_unbind_handle(sc->sc_hdr_dma_handle);
out_bind:
	ddi_dma_mem_free(&sc->sc_hdr_dma_acch);
out_mem:
	ddi_dma_free_handle(&sc->sc_hdr_dma_handle);
out:
	return (r);
#if 0
err_reqs:
#define D(map)								\
	do {								\
		if (sc->sc_ ##map) {					\
			bus_dmamap_destroy(vsc->sc_dmat, sc->sc_ ##map); \
			sc->sc_ ##map = NULL;				\
		}							\
	} while (0)
	D(ctrl_tbl_mc_dmamap);
	D(ctrl_tbl_uc_dmamap);
	D(ctrl_rx_dmamap);
	D(ctrl_status_dmamap);
	D(ctrl_cmd_dmamap);
	for (i = 0; i < txqsize; i++) {
		D(tx_dmamaps[i]);
		D(txhdr_dmamaps[i]);
	}
	for (i = 0; i < rxqsize; i++) {
		D(rx_dmamaps[i]);
		D(rxhdr_dmamaps[i]);
	}
#undef D
	if (sc->sc_arrays) {
		kmem_free(sc->sc_arrays, allocsize2);
		sc->sc_arrays = 0;
	}
err_dmamem_map:
	bus_dmamem_unmap(vsc->sc_dmat, sc->sc_hdrs, allocsize);
err_dmamem_alloc:
	bus_dmamem_free(vsc->sc_dmat, &sc->sc_hdr_segs[0], 1);
err_none:
	return -1;
#endif
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
	return DDI_FAILURE;
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

mblk_t *
virtio_net_tx(void *arg, mblk_t *mp)
{
	TRACE;
	return NULL;
#if 0
	afe_t	*afep = arg;
	mblk_t	*nmp;

	mutex_enter(&afep->afe_xmtlock);

	if (afep->afe_flags & AFE_SUSPENDED) {
		while ((nmp = mp) != NULL) {
			afep->afe_carrier_errors++;
			mp = mp->b_next;
			freemsg(nmp);
		}
		mutex_exit(&afep->afe_xmtlock);
		return (NULL);
	}

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!afe_send(afep, mp)) {
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}
	mutex_exit(&afep->afe_xmtlock);

	return (mp);
#endif
}

int
virtio_net_start(void *arg)
{
	struct vioif_softc *sc = arg;

	TRACE;

//	virtio_net_link_up(sc);

	mac_link_update(sc->sc_mac_handle, LINK_STATE_UP);

	/* On start, pre-fill the rx queue. */


	return (DDI_SUCCESS);
#if 0
	afe_t	*afep = arg;

	/* grab exclusive access to the card */
	mutex_enter(&afep->afe_intrlock);
	mutex_enter(&afep->afe_xmtlock);

	afe_startall(afep);
	afep->afe_flags |= AFE_RUNNING;

	mutex_exit(&afep->afe_xmtlock);
	mutex_exit(&afep->afe_intrlock);

	mii_start(afep->afe_mii);

	return (0);
#endif
}

void
virtio_net_stop(void *arg)
{
	struct vioif_softc *sc = arg;
	TRACE;
	
//	virtio_net_link_down(sc);
	mac_link_update(sc->sc_mac_handle, LINK_STATE_UP);
	return;
#if 0
	afe_t	*afep = arg;

	mii_stop(afep->afe_mii);

	/* exclusive access to the hardware! */
	mutex_enter(&afep->afe_intrlock);
	mutex_enter(&afep->afe_xmtlock);

	afe_stopall(afep);
	afep->afe_flags &= ~AFE_RUNNING;

	mutex_exit(&afep->afe_xmtlock);
	mutex_exit(&afep->afe_intrlock);
#endif
}


static int
virtio_net_stat(void *arg, uint_t stat, uint64_t *val)
{
	TRACE;
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

	cmn_err(CE_NOTE, "val = %llu\n", *val);

	return (DDI_SUCCESS);

#if 0
	afe_t	*afep = arg;

	mutex_enter(&afep->afe_xmtlock);
	if ((afep->afe_flags & (AFE_RUNNING|AFE_SUSPENDED)) == AFE_RUNNING)
		afe_reclaim(afep);
	mutex_exit(&afep->afe_xmtlock);

	if (mii_m_getstat(afep->afe_mii, stat, val) == 0) {
		return (0);
	}
	switch (stat) {
	case MAC_STAT_MULTIRCV:
		*val = afep->afe_multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = afep->afe_brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		*val = afep->afe_multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = afep->afe_brdcstxmt;
		break;

	case MAC_STAT_IPACKETS:
		*val = afep->afe_ipackets;
		break;

	case MAC_STAT_RBYTES:
		*val = afep->afe_rbytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = afep->afe_opackets;
		break;

	case MAC_STAT_OBYTES:
		*val = afep->afe_obytes;
		break;

	case MAC_STAT_NORCVBUF:
		*val = afep->afe_norcvbuf;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = 0;
		break;

	case MAC_STAT_COLLISIONS:
		*val = afep->afe_collisions;
		break;

	case MAC_STAT_IERRORS:
		*val = afep->afe_errrcv;
		break;

	case MAC_STAT_OERRORS:
		*val = afep->afe_errxmt;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = afep->afe_align_errors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = afep->afe_fcs_errors;
		break;

	case ETHER_STAT_SQE_ERRORS:
		*val = afep->afe_sqe_errors;
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = afep->afe_defer_xmts;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val = afep->afe_first_collisions;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = afep->afe_multi_collisions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = afep->afe_tx_late_collisions;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = afep->afe_ex_collisions;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		*val = afep->afe_macxmt_errors;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		*val = afep->afe_carrier_errors;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = afep->afe_toolong_errors;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = afep->afe_macrcv_errors;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = afep->afe_overflow;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = afep->afe_underflow;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = afep->afe_runt;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		*val = afep->afe_jabber;
		break;

	default:
		return (ENOTSUP);
	}
	return (0);
#endif
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
virtio_net_show_features(struct vioif_softc *sc)
{
	virtio_show_features(&sc->sc_virtio);

	dev_err(sc->sc_dev, CE_NOTE, "Virtio Net features:");

	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_CSUM)
		dev_err(sc->sc_dev, CE_NOTE, "CSUM");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_GUEST_CSUM)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_CSUM");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_MAC)
		dev_err(sc->sc_dev, CE_NOTE, "MAC");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_GSO)
		dev_err(sc->sc_dev, CE_NOTE, "GSO");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_GUEST_TSO4)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_TSO4");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_GUEST_TSO6)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_TSO6");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_GUEST_ECN)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_ECN");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_GUEST_UFO)
		dev_err(sc->sc_dev, CE_NOTE, "GUEST_UFO");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_HOST_TSO4)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_TSO4");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_HOST_TSO6)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_TSO6");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_HOST_ECN)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_ECN");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_HOST_UFO)
		dev_err(sc->sc_dev, CE_NOTE, "HOST_UFO");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_MRG_RXBUF)
		dev_err(sc->sc_dev, CE_NOTE, "MRG_RXBUF");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_STATUS)
		dev_err(sc->sc_dev, CE_NOTE, "STATUS");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_CTRL_VQ)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_VQ");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_CTRL_RX)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_RX");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_CTRL_VLAN)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_VLAN");
	if (sc->sc_virtio.sc_features & VIRTIO_NET_F_CTRL_RX_EXTRA)
		dev_err(sc->sc_dev, CE_NOTE, "CTRL_RX_EXTRA");
}

/*
 * Find out which features are supported by the device and
 * chose which ones we wish to use.
 */
static int
virtio_net_dev_features(struct vioif_softc *sc)
{
	virtio_negotiate_features(&sc->sc_virtio,
			VIRTIO_NET_F_MAC |
			VIRTIO_NET_F_STATUS |
//			VIRTIO_NET_F_CTRL_VQ |
//			VIRTIO_NET_F_CTRL_RX |
			VIRTIO_F_NOTIFY_ON_EMPTY |
			VRING_DESC_F_INDIRECT);

#if 0
	if (!(sc->sc.features & VIRTIO_RING_F_INDIRECT_DESC)) {
		dev_err(sc->sc_dev, CE_WARN,
			"Virtual device does not support indirect descriptors - host too old");
		return (DDI_FAILURE);
	}
#endif

	virtio_net_show_features(sc);

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
	int ret, instance, type, intr_types;
	struct vioif_softc *sc;
	mac_register_t *macp;
	ddi_acc_handle_t pci_conf;
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
	/* Duplicate for faster access / less typing */
	sc->sc_dev = devinfo;
	sc->sc_virtio.sc_dev = devinfo;

	ret = pci_config_setup(devinfo, &pci_conf);
	if (ret) {
		dev_err(devinfo, CE_WARN, "unable to setup PCI config handle");
		goto exit_pci_conf;

	}

	ret = virtio_net_match(devinfo, pci_conf);
	if (ret)
		goto exit_match;

	pci_config_teardown(&pci_conf);

	/* Determine which types of interrupts supported */
	ret = ddi_intr_get_supported_types(devinfo, &intr_types);
	if ((ret != DDI_SUCCESS) || (!(intr_types & DDI_INTR_TYPE_FIXED))) {
		dev_err(devinfo, CE_WARN, "fixed type interrupt is not supported");
		goto exit_inttype;
	}

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

	ret = virtio_alloc_vq(&sc->sc_virtio, &sc->sc_vq[0], 0, 2, "rx");
	if (ret) {
		goto exit_alloc1;
	}

	sc->sc_nvqs = 1;
//	sc->sc_virtio_vq[0].vq_done = vioif_rx_vq_done;

	if (virtio_alloc_vq(&sc->sc_virtio, &sc->sc_vq[1], 1,
		VIRTIO_NET_TX_MAXNSEGS + 1, "tx") != 0) {
		goto exit_alloc2;
	}
	sc->sc_nvqs = 2;
//	sc->sc_virtio_vq[1].vq_done = vioif_tx_vq_done;
	virtio_start_vq_intr(&sc->sc_vq[0]);
	virtio_stop_vq_intr(&sc->sc_vq[1]); /* not urgent; do it later */
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
	if (virtio_net_alloc_mems(sc))
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
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

	ret = mac_register(macp, &sc->sc_mac_handle);
	if (ret) {
		dev_err(devinfo, CE_WARN, "Failed to register the device");
		goto exit_register;
	}

	sc->sc_macp = macp;

	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	return (DDI_SUCCESS);

exit_register:
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
exit_map:
exit_inttype:
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

	TRACE;
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
	virtio_free_vq(&sc->sc_virtio, &sc->sc_vq[1]);
	virtio_free_vq(&sc->sc_virtio, &sc->sc_vq[0]);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
//	pci_config_teardown(&sc->sc_virtio.pci_conf);
	kmem_free(sc, sizeof (struct vioif_softc));

	return (DDI_SUCCESS);
}
