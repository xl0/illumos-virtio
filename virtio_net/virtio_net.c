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

#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#include "virtiovar.h"
#include "virtioreg.h"

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
/*
 * This is the string displayed by modinfo, etc.
 */
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
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

typedef struct virtio_net {
	struct virtio_softc	sc;
} virtio_net_t;

/*
 * _init
 *
 * Solaris standard _init function for a device driver
 */
int
_init(void)
{
	int ret = 0;

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
	return (mod_info(&modlinkage, pModinfo));
}

/*
 * virtio_net_attach
 * @devinfo: pointer to dev_info_t structure
 * @cmd: attach command to process
 */
static int
virtio_net_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int ret = DDI_SUCCESS, instance, type, intr_types;
	virtio_net_t *vnet;

	instance = ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		cmn_err(CE_WARN, "resume unsupported yet");
		ret = DDI_FAILURE;
		goto _exit0;

	default:
		cmn_err(CE_WARN, "cmd 0x%x unrecognized", cmd);
		ret = DDI_FAILURE;
		goto _exit0;
	}

	vnet = kmem_zalloc(sizeof (virtio_net_t), KM_SLEEP);
	ddi_set_driver_private(devinfo, vnet);
	vnet->sc.devinfo = devinfo;

	/* Determine which types of interrupts supported */
	ret = ddi_intr_get_supported_types(devinfo, &intr_types);
	if ((ret != DDI_SUCCESS) || (!(intr_types & DDI_INTR_TYPE_FIXED))) {
		cmn_err(CE_WARN, "fixed type interrupt is not supported");
		goto _exit1;
	}

	/* map BAR0 */
	ret = ddi_regs_map_setup(devinfo, 1, (caddr_t *)&vnet->sc.bar0,
	    (offset_t)0, (offset_t)0, &virtio_net_attr, &vnet->sc.bar0_handle);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "unable to map bar0: [%d]", ret);
		goto _exit1;
	}

	/* reset to a known state */
	virtio_set_status(&vnet->sc, 0);
	virtio_set_status(&vnet->sc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&vnet->sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	ret = pci_config_setup(devinfo, &vnet->sc.cfg_handle);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "unable to map pci config space: [%d]", ret);
		goto _exit2;
	}

	/* detect and print virtio type to the log */
	virtio_report_dev(&vnet->sc);

	ddi_report_dev(devinfo);
	instance = ddi_get_instance(devinfo);

	return (DDI_SUCCESS);

_exit2:
	ddi_regs_map_free(&vnet->sc.bar0_handle);
_exit1:
	kmem_free(vnet, sizeof (virtio_net_t));
_exit0:
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
static int
virtio_net_quiesce(dev_info_t *devinfo)
{
	virtio_net_t *dp =
	    (virtio_net_t *)ddi_get_driver_private(devinfo);

	/* FIXME: not implemented */

	return (DDI_FAILURE);
}

/*
 * virtio_net_detach
 * @devinfo: pointer to dev_info_t structure
 * @cmd: attach command to process
 */
static int
virtio_net_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	virtio_net_t *vnet =
	    (virtio_net_t *)ddi_get_driver_private(devinfo);

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

	ddi_remove_minor_node(vnet->sc.devinfo, NULL);
	pci_config_teardown(&vnet->sc.cfg_handle);
	ddi_regs_map_free(&vnet->sc.bar0_handle);
	kmem_free(vnet, sizeof (virtio_net_t));

	return (DDI_SUCCESS);
}
