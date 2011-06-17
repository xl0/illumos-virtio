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
 * Copyright (c) 2011, Nexenta Systems, Inc. All rights reserved.
 */


#include <sys/modctl.h>
#include <sys/blkdev.h>
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
#include "virtiovar.h"
#include "virtioreg.h"
#include "util.h"

/* Feature bits */
#define VIRTIO_BLK_F_BARRIER    (1<<0)
#define VIRTIO_BLK_F_SIZE_MAX   (1<<1)
#define VIRTIO_BLK_F_SEG_MAX    (1<<2)
#define VIRTIO_BLK_F_GEOMETRY   (1<<4)
#define VIRTIO_BLK_F_RO         (1<<5)
#define VIRTIO_BLK_F_BLK_SIZE   (1<<6)
#define VIRTIO_BLK_F_SCSI       (1<<7)
#define VIRTIO_BLK_F_FLUSH      (1<<9)
#define VIRTIO_BLK_F_SECTOR_MAX (1<<10)

/* Configuration registers */
#define VIRTIO_BLK_CONFIG_CAPACITY      0 /* 64bit */
#define VIRTIO_BLK_CONFIG_SIZE_MAX      8 /* 32bit */
#define VIRTIO_BLK_CONFIG_SEG_MAX       12 /* 32bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_C    16 /* 16bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_H    18 /* 8bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_S    19 /* 8bit */
#define VIRTIO_BLK_CONFIG_BLK_SIZE      20 /* 32bit */
#define VIRTIO_BLK_CONFIG_SECTOR_MAX    24 /* 32bit */

/* Command */
#define VIRTIO_BLK_T_IN			0
#define VIRTIO_BLK_T_OUT		1
#define VIRTIO_BLK_T_SCSI_CMD		2
#define VIRTIO_BLK_T_SCSI_CMD_OUT	3
#define VIRTIO_BLK_T_FLUSH		4
#define VIRTIO_BLK_T_FLUSH_OUT		5
#define VIRTIO_BLK_T_GET_ID		8
#define VIRTIO_BLK_T_BARRIER		0x80000000

#define VIRTIO_BLK_ID_BYTES	20 /* devid */

/* Statuses */
#define VIRTIO_BLK_S_OK		0
#define VIRTIO_BLK_S_IOERR	1
#define VIRTIO_BLK_S_UNSUPP	2

#define MAXPHYS			(1024*1024)
#define MAXINDIRECT		(128)

/*
 * Static Variables.
 */
static char vioblk_stream_ident[] = "VirtIO block driver";

/* Request header structure */
struct vioblk_req_hdr {
	uint32_t		type;   /* VIRTIO_BLK_T_* */
	uint32_t		ioprio;
	uint64_t		sector;
};

struct vioblk_req {
	struct vioblk_req_hdr	hdr;
	uint8_t			status;
	uint8_t			unused[3];
	unsigned int		ndmac;
	ddi_dma_handle_t	dmah;
	ddi_dma_handle_t	bd_dmah;
	ddi_dma_cookie_t	dmac;
	bd_xfer_t		*xfer;
};

struct vioblk_stats {
	struct kstat_named	sts_rw_outofmappings;
	struct kstat_named	sts_rw_outofmemory;
	struct kstat_named	sts_rw_badoffset;
	struct kstat_named	sts_rw_queuemax;
	struct kstat_named	sts_rw_cookiesmax;
	struct kstat_named	sts_rw_cacheflush;
	struct kstat_named	sts_intr_queuemax;
	struct kstat_named	sts_intr_total;
	struct kstat_named	sts_io_errors;
	struct kstat_named	sts_unsupp_errors;
	struct kstat_named	sts_nxio_errors;
};

struct vioblk_lstats {
	uint64_t		rw_cacheflush;
	uint64_t		intr_total;
	unsigned int		rw_cookiesmax;
	unsigned int		intr_queuemax;
	unsigned int		io_errors;
	unsigned int		unsupp_errors;
	unsigned int		nxio_errors;
};

struct vioblk_softc {
	dev_info_t		*sc_dev; /* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;
	struct virtqueue	*sc_vq;
	bd_handle_t		bd_h;
	struct vioblk_req	*sc_reqs;
	struct vioblk_stats	*ks_data;
	kstat_t                 *sc_intrstat;
	uint64_t		sc_capacity;
	uint64_t		sc_nblks;
	struct vioblk_lstats	sc_stats;
	short			sc_blkflags;
	int			sc_readonly;
	int			sc_blk_size;
	int			sc_seg_max;
	int			sc_size_max;
	int			sc_sector_max;
	int			sc_maxxfer;
	kmutex_t		lock_devid;
	kcondvar_t		cv_devid;
	bd_xfer_t		xfer_devid;
	char			devid[VIRTIO_BLK_ID_BYTES + 1];
};

static int vioblk_read(void *arg, bd_xfer_t *xfer);
static int vioblk_write(void *arg, bd_xfer_t *xfer);
static int vioblk_flush(void *arg, bd_xfer_t *xfer);
static int vioblk_dump(void *arg, bd_xfer_t *xfer);
static void vioblk_driveinfo(void *arg, bd_drive_t *drive);
static int vioblk_mediainfo(void *arg, bd_media_t *media);
static int vioblk_devid_init(void *, dev_info_t *, ddi_devid_t *);

static bd_ops_t vioblk_ops = {
	BD_OPS_VERSION_0,
	vioblk_driveinfo,
	vioblk_mediainfo,
	vioblk_devid_init,
	vioblk_flush,
	vioblk_read,
	vioblk_write,
	vioblk_dump
};

static int vioblk_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioblk_detach(dev_info_t *, ddi_detach_cmd_t);
static int vioblk_quiesce(dev_info_t *);

static struct dev_ops vioblk_stream_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,	/* identify */
	nulldev,	/* probe */
	vioblk_attach,	/* attach */
	vioblk_detach,	/* detach */
	nodev,		/* reset */
	NULL,		/* cb_ops */
	NULL,		/* bus_ops */
	NULL,		/* power */
	vioblk_quiesce	/* quiesce */
};

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	vioblk_stream_ident,    /* short description */
	&vioblk_stream_ops	/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL,
	},
};

ddi_device_acc_attr_t vioblk_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,      /* virtio is always native byte order */
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t vioblk_req_dma_attr = {
	DMA_ATTR_V0,           /* Version number */
	0,	               /* low address */
	0xFFFFFFFFFFFFFFFFull, /* high address */
	0x00000000FFFFFFFFull, /* counter register max */
	VIRTIO_PAGE_SIZE,      /* page alignment */
	0x1c,                  /* burst sizes: 1 - 32 */
	0x1,                   /* minimum transfer size */
	0xFF,                  /* max transfer size */
	0xFFFFFFFFFFFFFFFFull, /* address register max */
	1,	               /* dma_attr_sgllen	*/
	1,                     /* device operates on bytes */
	DDI_DMA_FORCE_PHYSICAL /* dma_attr_flags */
};

static ddi_dma_attr_t vioblk_bd_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x00000000FFFFFFFFull,		/* dma_attr_count_max	*/
	VIRTIO_PAGE_SIZE,		/* dma_attr_align	*/
	0x1c,				/* dma_attr_burstsizes	*/
	0x1,				/* dma_attr_minxfer	*/
	0xFFFFFFFF,			/* dma_attr_maxxfer	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg		*/
	0x7FFFFFFF,			/* dma_attr_sgllen	*/
	1,				/* dma_attr_granular	*/
	DDI_DMA_FORCE_PHYSICAL		/* dma_attr_flags       */
};

static int
vioblk_rw_indirect(struct vioblk_softc *sc, bd_xfer_t *xfer, int type,
		   uint32_t len)
{
	struct vioblk_req *req;
	struct vq_entry *ve_hdr;
	unsigned int ncookies;
	ddi_dma_cookie_t dma_cookie;
	int total_cookies, ret, write;

	write = (type == VIRTIO_BLK_T_OUT ||
		 type == VIRTIO_BLK_T_FLUSH_OUT) ? 1 : 0;
	ncookies = 0;
	total_cookies = 2;

	if ((xfer->x_blkno + xfer->x_nblks) > sc->sc_nblks) {
		sc->ks_data->sts_rw_badoffset.value.ui64++;
		return (EINVAL);
	}

	/* allocate top entry */
	ve_hdr = vq_alloc_entry(sc->sc_vq);
	if (!ve_hdr) {
		sc->ks_data->sts_rw_outofmemory.value.ui64++;
		goto exit_nomem0;
	}

	/* getting request */
	req = &sc->sc_reqs[ve_hdr->qe_index];
	req->hdr.type = type;
	req->hdr.ioprio = 0;
	req->hdr.sector = xfer->x_blkno;
	req->xfer = xfer;

	if (len > 0) {
		ret = ddi_dma_addr_bind_handle(req->bd_dmah, NULL,
		    (caddr_t)xfer->x_kaddr, len,
		    (write ? DDI_DMA_WRITE : DDI_DMA_READ) |
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0, &dma_cookie,
		    &ncookies);
		switch (ret) {
		case DDI_DMA_MAPPED:
			/* everything's fine */
			break;

		case DDI_DMA_NORESOURCES:
			sc->ks_data->sts_rw_outofmappings.value.ui64++;
			goto exit_nomem;

		case DDI_DMA_NOMAPPING:
		case DDI_DMA_INUSE:
		case DDI_DMA_TOOBIG:
		default:
			sc->ks_data->sts_rw_outofmappings.value.ui64++;
			goto exit_nomem;
		}
	}

	virtio_ve_set_indirect(ve_hdr, ncookies + 2, B_TRUE);

	/* sending header */
	ddi_dma_sync(req->dmah, 0, sizeof(struct vioblk_req_hdr),
		DDI_DMA_SYNC_FORDEV);
	virtio_ve_add_buf(ve_hdr, req->dmac.dmac_laddress,
			  sizeof(struct vioblk_req_hdr), B_TRUE);

	/* sending payload */
	if(len > 0) {
		virtio_ve_add_cookie(ve_hdr, req->bd_dmah, dma_cookie,
		    ncookies, write ? B_TRUE : B_FALSE);
		total_cookies += ncookies;
	}

	virtio_ve_add_buf(ve_hdr,
		req->dmac.dmac_laddress + sizeof(struct vioblk_req_hdr),
		sizeof(uint8_t), B_FALSE);

	/* sending the whole chain to the device */
	virtio_push_chain(ve_hdr, B_TRUE);

	if (sc->sc_stats.rw_cookiesmax < total_cookies)
		sc->sc_stats.rw_cookiesmax = total_cookies;

	return (DDI_SUCCESS);

exit_nomem:
	virtio_free_chain(ve_hdr);
exit_nomem0:
	return (ENOMEM);
}

static int
vioblk_rw(struct vioblk_softc *sc, bd_xfer_t *xfer, int type, uint32_t len)
{
	struct vioblk_req *req;
	struct vq_entry *ve, *ve_hdr, *ve_next;
	unsigned int ncookies;
	ddi_dma_cookie_t dma_cookie;
	int total_cookies, ret, dma_bound, write;

	write = (type == VIRTIO_BLK_T_OUT ||
		 type == VIRTIO_BLK_T_FLUSH_OUT) ? 1 : 0;
	dma_bound = 0;
	total_cookies = 2;

	if ((xfer->x_blkno + xfer->x_nblks) > sc->sc_nblks) {
		sc->ks_data->sts_rw_badoffset.value.ui64++;
		return (EINVAL);
	}

	/* allocate top entry */
	ve_hdr = vq_alloc_entry(sc->sc_vq);
	if (!ve_hdr) {
		sc->ks_data->sts_rw_outofmemory.value.ui64++;
		goto exit_nomem0;
	}

	/* getting request */
	req = &sc->sc_reqs[ve_hdr->qe_index];
	req->xfer = xfer;

	/* header is pre-mapped */
	req->hdr.type = type;
	req->hdr.ioprio = 0;
	req->hdr.sector = xfer->x_blkno;

	ve = ve_hdr;

	/* sending header */
	ddi_dma_sync(req->dmah, 0, sizeof(struct vioblk_req_hdr),
		DDI_DMA_SYNC_FORDEV);
	virtio_ve_set(ve, req->dmac.dmac_laddress,
			  sizeof(struct vioblk_req_hdr), B_TRUE);

	/* sending payload */
	if (len > 0) {
		ve_next = vq_alloc_entry(sc->sc_vq);
		if (!ve_next) {
			sc->ks_data->sts_rw_outofmemory.value.ui64++;
			goto exit_nomem;
		}
		ve->qe_next = ve_next;
		ve = ve_next;

		ret = ddi_dma_addr_bind_handle(req->bd_dmah, NULL,
		    (caddr_t)xfer->x_kaddr, len,
		    (write ? DDI_DMA_WRITE : DDI_DMA_READ) |
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0, &dma_cookie,
		    &ncookies);
		switch (ret) {
		case DDI_DMA_MAPPED:
			/* everything's fine */
			break;

		case DDI_DMA_NORESOURCES:
			sc->ks_data->sts_rw_outofmappings.value.ui64++;
			goto exit_nomem_dma;

		case DDI_DMA_NOMAPPING:
		case DDI_DMA_INUSE:
		case DDI_DMA_TOOBIG:
		default:
			sc->ks_data->sts_rw_outofmappings.value.ui64++;
			goto exit_nomem_dma;
		}
		dma_bound = 1;
		total_cookies += ncookies;

		while (ncookies) {
			/* going through all the cookies of payload next... */
			ASSERT(dma_cookie.dmac_laddress);
			virtio_ve_set(ve, dma_cookie.dmac_laddress,
			    dma_cookie.dmac_size, write ?
					B_TRUE : B_FALSE);
			total_cookies++;

			if (--ncookies) {
				ddi_dma_nextcookie(req->bd_dmah, &dma_cookie);

				ve_next = vq_alloc_entry(sc->sc_vq);
				if (!ve_next) {
					sc->ks_data->
					    sts_rw_outofmemory.value.ui64++;
					goto exit_nomem_dma;
				}
				ve->qe_next = ve_next;
				ve = ve_next;
			}

		}
	}

	/* sending status */
	ve_next = vq_alloc_entry(sc->sc_vq);
	if (!ve_next) {
		sc->ks_data->sts_rw_outofmemory.value.ui64++;
		goto exit_nomem_dma;
	}
	ve->qe_next = ve_next;
	ve = ve_next;

	virtio_ve_set(ve,
		req->dmac.dmac_laddress + sizeof(struct vioblk_req_hdr),
		sizeof(uint8_t), B_FALSE);

	/* sending the whole chain to the device */
	virtio_push_chain(ve_hdr, B_TRUE);

	if (sc->sc_stats.rw_cookiesmax < total_cookies)
		sc->sc_stats.rw_cookiesmax = total_cookies;

	return (DDI_SUCCESS);

exit_nomem_dma:
	if (dma_bound)
		ddi_dma_unbind_handle(req->bd_dmah);
exit_nomem:
	virtio_free_chain(ve_hdr);
exit_nomem0:
	return (ENOMEM);
}

static int
vioblk_read(void *arg, bd_xfer_t *xfer)
{
	int ret;
	struct vioblk_softc *sc = (void *)arg;

	if (sc->sc_virtio.sc_indirect)
		ret = vioblk_rw_indirect(sc, xfer, VIRTIO_BLK_T_IN,
			xfer->x_nblks * sc->sc_blk_size);
	else
		ret = vioblk_rw(sc, xfer, VIRTIO_BLK_T_IN,
				xfer->x_nblks * sc->sc_blk_size);
	return (ret);
}

static int
vioblk_write(void *arg, bd_xfer_t *xfer)
{
	int ret;
	struct vioblk_softc *sc = (void *)arg;

	if (sc->sc_virtio.sc_indirect)
		ret = vioblk_rw_indirect(sc, xfer, VIRTIO_BLK_T_OUT,
			xfer->x_nblks * sc->sc_blk_size);
	else
		ret = vioblk_rw(sc, xfer, VIRTIO_BLK_T_OUT,
			xfer->x_nblks * sc->sc_blk_size);
	return (ret);
}

static int
vioblk_flush(void *arg, bd_xfer_t *xfer)
{
	int ret;
	struct vioblk_softc *sc = (void *)arg;

	if (sc->sc_virtio.sc_indirect)
		ret = vioblk_rw_indirect(sc, xfer, VIRTIO_BLK_T_FLUSH_OUT,
			xfer->x_nblks * sc->sc_blk_size);
	else
		ret = vioblk_rw(sc, xfer, VIRTIO_BLK_T_FLUSH_OUT,
			xfer->x_nblks * sc->sc_blk_size);
	if (!ret)
		sc->sc_stats.rw_cacheflush++;
	return (ret);
}

static int
vioblk_dump(void *arg, bd_xfer_t *xfer_in)
{
	int ret;
	size_t len;
	struct vioblk_softc *sc = (void *)arg;
	struct vq_entry *ve;

	if (sc->sc_virtio.sc_indirect)
		ret = vioblk_rw_indirect(sc, xfer_in, VIRTIO_BLK_T_OUT,
			xfer_in->x_nblks * sc->sc_blk_size);
	else
		ret = vioblk_rw(sc, xfer_in, VIRTIO_BLK_T_OUT,
			xfer_in->x_nblks * sc->sc_blk_size);
	if (ret) {
		dev_err(sc->sc_dev, CE_WARN,
			"Cannot send dump request %d", xfer_in->x_blkno);
		return (ret);
	}

	while ((ve = virtio_pull_chain(sc->sc_vq, &len))) {
		struct vioblk_req *req = &sc->sc_reqs[ve->qe_index];

		/* syncing payload and freeing DMA handle */
		if (req->bd_dmah)
			ddi_dma_unbind_handle(req->bd_dmah);

		/* syncing status */
		ddi_dma_sync(req->dmah, sizeof(struct vioblk_req_hdr),
			     sizeof(uint8_t), DDI_DMA_SYNC_FORKERNEL);

		/* returning chain back to virtio */
		virtio_free_chain(ve);
	}

	return (DDI_SUCCESS);
}

static void
vioblk_driveinfo(void *arg, bd_drive_t *drive)
{
	struct vioblk_softc *sc = (void *)arg;

	drive->d_qsize = sc->sc_virtio.sc_indirect ? MAXINDIRECT : 4;
	drive->d_maxxfer = sc->sc_maxxfer;
	drive->d_removable = B_FALSE;
	drive->d_hotpluggable = B_TRUE;
	drive->d_target = 0;
	drive->d_lun = 0;
}

static int
vioblk_mediainfo(void *arg, bd_media_t *media)
{
	struct vioblk_softc *sc = (void *)arg;

	media->m_nblks = sc->sc_nblks;
	media->m_blksize = sc->sc_blk_size;
	media->m_readonly = sc->sc_readonly;
	return (0);
}

static int
vioblk_devid_init(void *arg, dev_info_t *devinfo, ddi_devid_t *devid)
{
	struct vioblk_softc *sc = (void *)arg;
	clock_t deadline;
	int ret;

	deadline = ddi_get_lbolt() + (clock_t)drv_usectohz(3 * 1000000);

	sc->xfer_devid.x_kaddr = sc->devid;
	sc->xfer_devid.x_nblks = 1;
	sc->xfer_devid.x_blkno = 0;

	mutex_enter(&sc->lock_devid);
	/* non-indirect call is fine here */
	ret = vioblk_rw(sc, &sc->xfer_devid, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_ID_BYTES);
	if (ret) {
		mutex_exit(&sc->lock_devid);
		return (ret);
	}

	/* wait for reply */
	ret = cv_timedwait(&sc->cv_devid, &sc->lock_devid, deadline);
	mutex_exit(&sc->lock_devid);

	/* timeout */
	if (ret < 0) {
		dev_err(devinfo, CE_WARN, "Cannot get devid from the device");
		return (ret);
	}

	ret = ddi_devid_init(devinfo, DEVID_ATA_SERIAL,
		VIRTIO_BLK_ID_BYTES, sc->devid, devid);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "Cannot build devid from the device");
		return (ret);
	}

	dev_err(sc->sc_dev, CE_NOTE,
		"devid %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
		sc->devid[0], sc->devid[1], sc->devid[2], sc->devid[3],
		sc->devid[4], sc->devid[5], sc->devid[6], sc->devid[7],
		sc->devid[8], sc->devid[9], sc->devid[10], sc->devid[11],
		sc->devid[12], sc->devid[13], sc->devid[14], sc->devid[15],
		sc->devid[16], sc->devid[17], sc->devid[18], sc->devid[19]);

	return (0);
}

static int
vioblk_match(dev_info_t *devinfo, ddi_acc_handle_t pconf)
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

	if (subdevice != PCI_PRODUCT_VIRTIO_BLOCK) {
		dev_err(devinfo, CE_NOTE,
			"Subsystem ID does not match: %x, expected %x",
			vendor, PCI_VENDOR_QUMRANET);
		dev_err(devinfo, CE_NOTE,
			"This is a virtio device, but not virtio-blk, skipping");

		return (DDI_FAILURE);
	}

	dev_err(devinfo, CE_NOTE, "Matched successfully");

	return (DDI_SUCCESS);
}

static void
vioblk_show_features(struct vioblk_softc *sc, uint32_t features)
{
	char buf[512];
	char *bufp;
	char *bufend = buf + sizeof(buf);

	bufp = virtio_show_features(&sc->sc_virtio,
			features, buf, sizeof(buf));


	bufp += snprintf(bufp, bufend - bufp, "Vioblk ( ");

	if (features & VIRTIO_BLK_F_BARRIER)
		bufp += snprintf(bufp, bufend - bufp, "BARRIER ");
	if (features & VIRTIO_BLK_F_SIZE_MAX)
		bufp += snprintf(bufp, bufend - bufp, "SIZE_MAX ");
	if (features & VIRTIO_BLK_F_SEG_MAX)
		bufp += snprintf(bufp, bufend - bufp, "SEG_MAX ");
	if (features & VIRTIO_BLK_F_GEOMETRY)
		bufp += snprintf(bufp, bufend - bufp, "GEOMETRY ");
	if (features & VIRTIO_BLK_F_RO)
		bufp += snprintf(bufp, bufend - bufp, "RO ");
	if (features & VIRTIO_BLK_F_BLK_SIZE)
		bufp += snprintf(bufp, bufend - bufp, "BLK_SIZE ");
	if (features & VIRTIO_BLK_F_SCSI)
		bufp += snprintf(bufp, bufend - bufp, "SCSI ");
	if (features & VIRTIO_BLK_F_FLUSH)
		bufp += snprintf(bufp, bufend - bufp, "FLUSH ");
	if (features & VIRTIO_BLK_F_SECTOR_MAX)
		bufp += snprintf(bufp, bufend - bufp, "SECTOR_MAX ");

	bufp += snprintf(bufp, bufend - bufp, ")");
	*bufp = '\0';

	dev_err(sc->sc_dev, CE_NOTE, "%s", buf);
}

static int
vioblk_dev_features(struct vioblk_softc *sc)
{
	uint32_t host_features;

	host_features = virtio_negotiate_features(&sc->sc_virtio,
	     (VIRTIO_BLK_F_RO |
	      VIRTIO_BLK_F_GEOMETRY |
	      VIRTIO_BLK_F_BLK_SIZE |
	      VIRTIO_BLK_F_FLUSH |
	      VIRTIO_BLK_F_SEG_MAX |
	      VIRTIO_BLK_F_SIZE_MAX));

	if (!(sc->sc_virtio.sc_features & VIRTIO_BLK_F_BLK_SIZE)) {
		dev_err(sc->sc_dev, CE_NOTE, "Error while negotiating host features");
		return (DDI_FAILURE);
	}

	dev_err(sc->sc_dev, CE_NOTE, "Host features:");
	vioblk_show_features(sc, host_features);

	dev_err(sc->sc_dev, CE_NOTE, "Negotiated features:");
	vioblk_show_features(sc, sc->sc_virtio.sc_features);

	return (DDI_SUCCESS);
}

/*
 * Interrupt service routine.
 */
uint_t vioblk_int_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *)arg1;
	struct vioblk_softc *sc = container_of(vsc,
			struct vioblk_softc, sc_virtio);

	struct vq_entry *ve;
	size_t len;
	int i = 0, error;


	while ((ve = virtio_pull_chain(sc->sc_vq, &len))) {
		struct vioblk_req *req = &sc->sc_reqs[ve->qe_index];
		bd_xfer_t *xfer = req->xfer;

		/* syncing payload and freeing DMA handle */
		if (req->bd_dmah)
			ddi_dma_unbind_handle(req->bd_dmah);

		/* syncing status */
		ddi_dma_sync(req->dmah, sizeof(struct vioblk_req_hdr),
			     sizeof(uint8_t), DDI_DMA_SYNC_FORKERNEL);

		/* returning chain back to virtio */
		virtio_free_chain(ve);

		/* returning payload back to blkdev */
		switch (req->status) {
			case VIRTIO_BLK_S_OK:
				error = 0;
				break;
			case VIRTIO_BLK_S_IOERR:
				error = EIO;
				sc->sc_stats.io_errors++;
				break;
			case VIRTIO_BLK_S_UNSUPP:
				sc->sc_stats.unsupp_errors++;
				error = ENOTTY;
				break;
			default:
				sc->sc_stats.nxio_errors++;
				error = ENXIO;
				break;
		}
		if (req->hdr.type == VIRTIO_BLK_T_GET_ID) {
			/* notify devid_init */
			mutex_enter(&sc->lock_devid);
			cv_broadcast(&sc->cv_devid);
			mutex_exit(&sc->lock_devid);
		} else
			bd_xfer_done(xfer, error);

		i++;
	}

	/* update stats */
	if (sc->sc_stats.intr_queuemax < i)
		sc->sc_stats.intr_queuemax = i;
	sc->sc_stats.intr_total++;

	return (DDI_INTR_CLAIMED);
}

uint_t vioblk_config_handler(caddr_t arg1, caddr_t arg2)
{
        /* We want to know if we ever get here. */
	TRACE;

	return (DDI_INTR_CLAIMED);
}

static int
vioblk_register_ints(struct vioblk_softc *sc)
{
	int ret;

	struct virtio_int_handler vioblk_conf_h = {
		vioblk_config_handler
	};

	struct virtio_int_handler vioblk_vq_h[] = {
		{ vioblk_int_handler },
		{ NULL }
	};

	ret = virtio_register_ints(&sc->sc_virtio,
		&vioblk_conf_h, vioblk_vq_h);

	return (ret);
}

static int
vioblk_alloc_reqs(struct vioblk_softc *sc)
{
	int i, qsize;

	qsize = sc->sc_vq->vq_num;

	sc->sc_reqs = kmem_zalloc(sizeof(struct vioblk_req) * qsize, KM_SLEEP);
	if (!sc->sc_reqs) {
		dev_err(sc->sc_dev, CE_WARN,
			"Failed to allocate the reqs buffers array");
		return (ENOMEM);
	}

	for (i = 0 ; i < qsize; i++) {
		struct vioblk_req *req = &sc->sc_reqs[i];

		if (ddi_dma_alloc_handle(sc->sc_dev, &vioblk_bd_dma_attr,
		    DDI_DMA_DONTWAIT, 0, &req->bd_dmah)) {

			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate bd dma handle for req "
				"buffer %d", i);
			goto exit;
		}

		if (ddi_dma_alloc_handle(sc->sc_dev, &vioblk_req_dma_attr,
			DDI_DMA_SLEEP, NULL, &req->dmah)) {

			dev_err(sc->sc_dev, CE_WARN,
				"Can't allocate dma handle for req "
				"buffer %d", i);
			goto exit;
		}

		if (ddi_dma_addr_bind_handle(req->dmah, NULL, (caddr_t)&req->hdr,
			sizeof(struct vioblk_req_hdr) + sizeof(uint8_t),
			DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
			NULL, &req->dmac, &req->ndmac)) {

			dev_err(sc->sc_dev, CE_WARN, "Can't bind req buffer %d", i);
			goto exit;
		}
	}

	return (0);

exit:
	for (i = 0; i < qsize; i++) {
		struct vioblk_req *req = &sc->sc_reqs[i];

		if (req->ndmac)
			ddi_dma_unbind_handle(req->dmah);

		if (req->dmah)
			ddi_dma_free_handle(&req->dmah);

		if (req->bd_dmah)
			ddi_dma_free_handle(&req->bd_dmah);
	}

	kmem_free(sc->sc_reqs, sizeof(struct vioblk_req) * qsize);
	return (ENOMEM);
}

static int
vioblk_free_reqs(struct vioblk_softc *sc)
{
	int i, qsize;

	qsize = sc->sc_vq->vq_num;

	for (i = 0; i < qsize; i++) {
		struct vioblk_req *req = &sc->sc_reqs[i];

		if (req->ndmac)
			ddi_dma_unbind_handle(req->dmah);

		if (req->dmah)
			ddi_dma_free_handle(&req->dmah);
	}

	kmem_free(sc->sc_reqs, sizeof(struct vioblk_req) * qsize);
	return (ENOMEM);
}

static int
vioblk_ksupdate(kstat_t *ksp, int rw)
{
	struct vioblk_softc *sc = ksp->ks_private;

	if (rw == KSTAT_WRITE) {
		/* nothing */
	} else {
		sc->ks_data->sts_rw_cookiesmax.value.ui32 =
			sc->sc_stats.rw_cookiesmax;
		sc->ks_data->sts_intr_queuemax.value.ui32 =
			sc->sc_stats.intr_queuemax;
		sc->ks_data->sts_unsupp_errors.value.ui32 =
			sc->sc_stats.unsupp_errors;
		sc->ks_data->sts_nxio_errors.value.ui32 =
			sc->sc_stats.nxio_errors;
		sc->ks_data->sts_io_errors.value.ui32 =
			sc->sc_stats.io_errors;
		sc->ks_data->sts_rw_cacheflush.value.ui64 =
			sc->sc_stats.rw_cacheflush;
		sc->ks_data->sts_intr_total.value.ui64 =
			sc->sc_stats.intr_total;
	}

	return (0);
}

static int
vioblk_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int ret, instance, intr_types;
	struct vioblk_softc *sc;
	struct virtio_softc *vsc;
	ddi_acc_handle_t pci_conf;
	struct vioblk_stats *ks_data;

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

	sc = kmem_zalloc(sizeof (struct vioblk_softc), KM_SLEEP);
	if (sc == NULL) {
		dev_err(devinfo, CE_WARN, "Cannot allocate softc memory");
		ret = DDI_FAILURE;
		goto exit;
	}
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

	ret = vioblk_match(devinfo, pci_conf);
	if (ret)
		goto exit_match;

	pci_config_teardown(&pci_conf);

	/* Determine which types of interrupts supported */
	ret = ddi_intr_get_supported_types(devinfo, &intr_types);
	if ((ret != DDI_SUCCESS) || (!(intr_types & DDI_INTR_TYPE_FIXED))) {
		dev_err(devinfo, CE_WARN, "fixed type interrupt is not supported");
		goto exit_inttype;
	}

	cv_init(&sc->cv_devid, NULL, CV_DRIVER, NULL);
	mutex_init(&sc->lock_devid, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Initialize interrupt kstat.  This should not normally fail, since
	 * we don't use a persistent stat.  We do it this way to avoid having
	 * to test for it at run time on the hot path.
	 */
	sc->sc_intrstat = kstat_create("vioblk", instance,
		"intrs", "controller", KSTAT_TYPE_NAMED,
		sizeof (struct vioblk_stats) / sizeof (kstat_named_t),
		KSTAT_FLAG_PERSISTENT);
	if (sc->sc_intrstat == NULL) {
		dev_err(devinfo, CE_WARN, "kstat_create failed");
		goto exit_intrstat;
	}
	ks_data = (struct vioblk_stats *)sc->sc_intrstat->ks_data;
	kstat_named_init(&ks_data->sts_rw_outofmemory,
			 "total_rw_outofmemory", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_rw_outofmappings,
			 "total_rw_outofmappings", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_rw_badoffset,
			 "total_rw_badoffset", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_intr_total,
			 "total_intr", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_io_errors,
			 "total_io_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_unsupp_errors,
			 "total_unsupp_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_nxio_errors,
			 "total_nxio_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_rw_cacheflush,
			 "total_rw_cacheflush", KSTAT_DATA_UINT64);
	kstat_named_init(&ks_data->sts_rw_cookiesmax,
			 "max_rw_cookies", KSTAT_DATA_UINT32);
	kstat_named_init(&ks_data->sts_intr_queuemax,
			 "max_intr_queue", KSTAT_DATA_UINT32);
	sc->ks_data = ks_data;
	sc->sc_intrstat->ks_private = sc;
	sc->sc_intrstat->ks_update = vioblk_ksupdate;
	kstat_install(sc->sc_intrstat);

	/* map BAR0 */
	ret = ddi_regs_map_setup(devinfo, 1, (caddr_t *)&sc->sc_virtio.sc_io_addr,
		0, 0, &vioblk_attr, &sc->sc_virtio.sc_ioh);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "unable to map bar0: [%d]", ret);
		goto exit_map;
	}

	virtio_device_reset(&sc->sc_virtio);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	ret = vioblk_dev_features(sc);
	if (ret)
		goto exit_features;

	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_RO)
		sc->sc_readonly = 1;
	else
		sc->sc_readonly = 0;

	sc->sc_capacity = virtio_read_device_config_8(&sc->sc_virtio,
		VIRTIO_BLK_CONFIG_CAPACITY);
	sc->sc_nblks = sc->sc_capacity;

	sc->sc_blk_size = DEV_BSIZE;
	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_BLK_SIZE) {
		sc->sc_blk_size = virtio_read_device_config_4(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_BLK_SIZE);
	}

	if (!(sc->sc_virtio.sc_features & VIRTIO_BLK_F_FLUSH)) {
		vioblk_ops.o_sync_cache = NULL;
	}

	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_GEOMETRY) {
		int ncyls, nheads, nsects;
		ncyls = virtio_read_device_config_2(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_GEOMETRY_C);
		nheads = virtio_read_device_config_1(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_GEOMETRY_H);
		nsects = virtio_read_device_config_1(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_GEOMETRY_S);
	}

	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_SEG_MAX) {
		sc->sc_seg_max = virtio_read_device_config_4(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_SEG_MAX);
		if(sc->sc_seg_max) {
			vioblk_bd_dma_attr.dma_attr_seg = sc->sc_seg_max;
		}
	}
	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_SIZE_MAX) {
		sc->sc_size_max = virtio_read_device_config_4(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_SIZE_MAX);
		if(sc->sc_size_max) {
			vioblk_bd_dma_attr.dma_attr_maxxfer = sc->sc_size_max;
		}
	}
	if (sc->sc_virtio.sc_features & VIRTIO_BLK_F_SECTOR_MAX) {
		sc->sc_sector_max = virtio_read_device_config_4(&sc->sc_virtio,
		    VIRTIO_BLK_CONFIG_SECTOR_MAX);
	}
	if (sc->sc_sector_max)
		sc->sc_maxxfer = sc->sc_sector_max * sc->sc_blk_size;
	else
		sc->sc_maxxfer = MAXPHYS;

	dev_err(devinfo, CE_NOTE, "nblks=%d blksize=%d maxxfer=%d "
		"dma_maxxfer %ld dma_segs %ld",
		sc->sc_nblks, sc->sc_blk_size, sc->sc_maxxfer,
		vioblk_bd_dma_attr.dma_attr_maxxfer,
		vioblk_bd_dma_attr.dma_attr_seg);

	sc->sc_vq = virtio_alloc_vq(&sc->sc_virtio, 0, 0,
				    MAXINDIRECT, "I/O request");
	if (sc->sc_vq == NULL) {
		goto exit_alloc1;
	}
	virtio_stop_vq_intr(sc->sc_vq);

	ret = vioblk_alloc_reqs(sc);
	if (ret) {
		goto exit_alloc2;
	}

	sc->bd_h = bd_alloc_handle(sc, &vioblk_ops, NULL, KM_SLEEP);
	if (sc->bd_h == NULL) {
		dev_err(devinfo, CE_WARN, "Failed to alocate blkdev");
		goto exit_alloc_bd;
	}

	/*
	 * Establish interrupt handler.
	 */
	if (vioblk_register_ints(sc)) {
		dev_err(devinfo, CE_WARN, "Unable to add interrupt");
		goto exit_int;
	}

	virtio_set_status(&sc->sc_virtio,
	    VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);
	virtio_start_vq_intr(sc->sc_vq);

	ret = bd_attach_handle(devinfo, sc->bd_h);
	if (ret != DDI_SUCCESS) {
		dev_err(devinfo, CE_WARN, "Failed to attach blkdev");
		goto exit_attach_bd;
	}

	return (DDI_SUCCESS);

exit_attach_bd:
	virtio_stop_vq_intr(sc->sc_vq);
	virtio_release_ints(&sc->sc_virtio);
exit_int:
	bd_free_handle(sc->bd_h);
exit_alloc_bd:
	vioblk_free_reqs(sc);
exit_alloc2:
	virtio_free_vq(sc->sc_vq);
exit_alloc1:
exit_features:
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_FAILED);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
exit_intrstat:
exit_map:
	kstat_delete(sc->sc_intrstat);
exit_inttype:
	mutex_destroy(&sc->lock_devid);
	cv_destroy(&sc->cv_devid);
exit_match:
exit_pci_conf:
	kmem_free(sc, sizeof (struct vioblk_softc));
exit:
	return (ret);
}

static int
vioblk_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct vioblk_softc *sc = ddi_get_driver_private(devinfo);

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

	(void) bd_detach_handle(sc->bd_h);
	virtio_stop_vq_intr(sc->sc_vq);
	virtio_release_ints(&sc->sc_virtio);
	vioblk_free_reqs(sc);
	virtio_free_vq(sc->sc_vq);
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);
	kstat_delete(sc->sc_intrstat);
	kmem_free(sc, sizeof (struct vioblk_softc));

	return (DDI_SUCCESS);
}

int
vioblk_quiesce(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

int
_init(void)
{
	int rv;

	bd_mod_init(&vioblk_stream_ops);

	if ((rv = mod_install(&modlinkage)) != 0) {
		bd_mod_fini(&vioblk_stream_ops);
	}

	return (rv);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		bd_mod_fini(&vioblk_stream_ops);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
