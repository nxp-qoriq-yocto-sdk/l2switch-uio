/*
 *
 * Seville UIO driver.
 *
 * Copyright (C) 2014 Vitesse Semiconductor Inc.
 * Copyright 2014 Freescale Semiconductor Inc.
 *
 * Author: Lars Povlsen (lpovlsen@vitesse.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * VITESSE SEMICONDUCTOR INC SHALL HAVE NO LIABILITY WHATSOEVER OF ANY
 * KIND ARISING OUT OF OR RELATED TO THE PROGRAM OR THE OPEN SOURCE
 * MATERIALS UNDER ANY THEORY OF LIABILITY.
 *
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/uio_driver.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>

#include <linux/platform_device.h>

#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/of_net.h>
#include <linux/of_address.h>

/* Seville's maximum number of available ports */
#define SEVILLE_PORTS_NR_MAX		10

/* Register used for remapper bypassing */
#define T1040_SCFG_ESGMIISELCR		0xffe0fc020

/* Bit masks used to for address remapper scfg_esgmiiselcr */
#define T1040_SCFG_ESGMIISELCR_ENA		0x20
#define T1040_SCFG_ESGMIISELCR_GMIISEL		0x80

#include "npi.h"
#include "phy_seville.h"

/* Timeout used to wait while MIIM controller becomes idle */
#define MIIM_TIMEOUT		1000000

#define DEVICE_NAME "seville"

struct uio_seville {
    struct uio_info uio;
    /* Private data */
    spinlock_t lock;
    unsigned long flags;
    const u8 *mac_addr;
    struct platform_device *pdev;
    struct npi_device *npi_dev;
    struct seville_port_info port_info;
};

static ssize_t show_mac_addr(struct device *dev,
		struct device_attribute *attr, char *buf)
{
    struct uio_seville *info;
    struct platform_device *pdev;

    if (!buf || !dev)
        return -EINVAL;

    pdev = to_platform_device(dev);
    if (!pdev) {
        pr_err(DEVICE_NAME" No platform device attached\n");
        return -EINVAL;
    }

    info = platform_get_drvdata(pdev);
    if (!info) {
        pr_err(DEVICE_NAME" No uio device attached\n");
        return -EINVAL;
    }

    return sysfs_format_mac(buf, (unsigned char *)info->mac_addr, ETH_ALEN);
}

/* Sysfs entry for L2Switch MAC address */
static DEVICE_ATTR(mac_address, S_IRUGO, &show_mac_addr, NULL);

static irqreturn_t seville_handler(int irq, struct uio_info *info)
{
    int handled;
    struct uio_seville *priv = info->priv;

    if (unlikely(!(ioread32(VTSS_DEVCPU_QS_REMAP_INTR_IDENT) & GR0))) {
         /* not our interrupt */
         handled = IRQ_NONE;
         goto __return;
    }

    if (likely(ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1)) {
        /* Disable interrupt */
        CLR_REG(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE, GR0);

        /* no need to hold the lock for read_thread here since we don't
         * modify its value. there is no problem if
         * read_thread becomes NULL after we check
         * it and before we wake up the sleeping thread
         */
        if (likely(priv->npi_dev->read_thread))
            wake_up_interruptible(&priv->npi_dev->npi_read_q);

        handled = IRQ_HANDLED;
        goto __return;
    }

    /* if we reached here, it means that interrupt was raised,
     * although there is no data pending; we should never reach here
     * However, since we are here we should clear the pending interrupt
     */
    SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_IDENT, GR0);

    handled = IRQ_HANDLED;

__return:
    return IRQ_RETVAL(handled);
}

static int seville_irqcontrol(struct uio_info *info, s32 irq_on)
{
    struct uio_seville *priv = info->priv;
    unsigned long flags;

    spin_lock_irqsave(&priv->lock, flags);
    if (irq_on) {
        if (test_and_clear_bit(0, &priv->flags)) {
            //printk("Seville: Enable IRQ\n");
            enable_irq(info->irq);
        }
    } else {
        if (!test_and_set_bit(0, &priv->flags)) {
            //printk("Seville: Disable IRQ\n");
            disable_irq(info->irq);
        }
    }
    spin_unlock_irqrestore(&priv->lock, flags);

    return 0;
}

static int seville_open(struct uio_info *info, struct inode *inode)
{
    struct uio_seville *priv;
    int rc;

    if (!info)
        return -EINVAL;

    priv = info->priv;
    if (!priv)
        return -EINVAL;

    rc = 0;
    spin_lock(&priv->lock);
    if (test_and_set_bit(1, &priv->flags))
        rc = -EBUSY;

    spin_unlock(&priv->lock);
    return rc;
}

static int seville_release(struct uio_info *info, struct inode *inode)
{
    struct uio_seville *priv;
    int rc;

    if (!info)
        return -EINVAL;

    priv = info->priv;
    if (!priv)
        return -EINVAL;

    rc = 0;
    spin_lock(&priv->lock);
    if (!test_and_clear_bit(1, &priv->flags))
        rc = -EINVAL;

    spin_unlock(&priv->lock);
    return rc;
}

static void __iomem *seville_of_io_remap(struct platform_device *pdev,
                                         struct uio_info *info,
                                         int index)
{
    void __iomem *addr = NULL;
#if defined(CONFIG_OF_ADDRESS)
    struct resource res;
    int ret;

    if ((ret = of_address_to_resource(pdev->dev.of_node, index, &res)) == 0) {
        info->mem[index].addr = res.start;
        info->mem[index].size = resource_size(&res);
        if ((addr = ioremap(info->mem[index].addr, info->mem[index].size))) {
            info->mem[index].internal_addr = addr;
            info->mem[index].memtype = UIO_MEM_PHYS;
            pr_devel("%s: %d: Mapped %pa size %pa to %p\n", DEVICE_NAME,
                     index, &info->mem[index].addr, &info->mem[index].size, addr);
        }
    } else {
        pr_warn("%s: memory map %d failed: error %d\n", DEVICE_NAME, index, -ret);
    }
#endif  /* CONFIG_OF_ADDRESS */
    return addr;
}

int vsc9953_mdio_write(struct uio_info *info, uint8_t phy_addr,
		uint8_t regnum, uint16_t value)
{
    int timeout = MIIM_TIMEOUT;

    /* Wait while MIIM controller becomes idle */
    while ((ioread32(VTSS_DEVCPU_GCB_MIIM_MII_STATUS(0)) &
            VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_OPR_PEND) &&
            --timeout)
        /* busy wait */;

    if (timeout == 0)
        return -EBUSY;

    /* Write the MIIM COMMAND register */
    iowrite32((0x1 << 31) | ((phy_addr & 0x1f) << 25) |
                ((regnum & 0x1f) << 20) | ((value & 0xffff) << 4) |
                (0x1 << 1), VTSS_DEVCPU_GCB_MIIM_MII_CMD(0));
    wmb();

    return 0;
}

int vsc9953_mdio_read(struct uio_info *info, uint8_t phy_addr,
		uint8_t regnum)
{
    int timeout = MIIM_TIMEOUT;
    int value;

    /* Wait while MIIM controller becomes idle */
    while ((ioread32(VTSS_DEVCPU_GCB_MIIM_MII_STATUS(0)) &
            VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_OPR_PEND) &&
            --timeout)
        /* busy wait */;

    if (timeout == 0)
        return -EBUSY;
    timeout = MIIM_TIMEOUT;

    /* Write the MIIM COMMAND register */
    iowrite32((0x1 << 31) | ((phy_addr & 0x1f) << 25) |
                ((regnum & 0x1f) << 20) | (0x2 << 1),
                VTSS_DEVCPU_GCB_MIIM_MII_CMD(0));
    wmb();

    udelay(1);

    /* Wait while read operation via the MIIM controller is in progress */
    while ((ioread32(VTSS_DEVCPU_GCB_MIIM_MII_STATUS(0)) &
            VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_BUSY) &&
            --timeout)
        /* busy wait */;

    if (timeout == 0)
        return -EBUSY;

    value = ioread32(VTSS_DEVCPU_GCB_MIIM_MII_DATA(0));

    if ((value & VTSS_M_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_SUCCESS) == 0)
        return value & VTSS_M_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_RDDATA;
    return -ENXIO;
}

static void vsc9953_lynx_init(struct device_node *mdio, struct uio_info *info)
{
    struct device_node *tbi_child;
    uint8_t phy_addr;
    int size;
    const void *prop;

    for_each_child_of_node(mdio, tbi_child) {
        prop = of_get_property(tbi_child, "reg", &size);
        if (!prop || size < sizeof(uint8_t)) {
            pr_err(DEVICE_NAME "unable to parse TBI-PHY address\n");
            return;
        }

        phy_addr = (uint8_t)be32_to_cpup(prop);
        /* Interface Mode Register */
        vsc9953_mdio_write(info, phy_addr, 0x14, 0x000b);
        /* Device Ability Register */
        vsc9953_mdio_write(info, phy_addr, 0x04, 0x01a1);
        /* Timer Upper Register */
        vsc9953_mdio_write(info, phy_addr, 0x13, 0x0003);
        /* Timer Lower Register */
        vsc9953_mdio_write(info, phy_addr, 0x12, 0x06a0);
        /* Control Register */
        vsc9953_mdio_write(info, phy_addr, 0x00, 0x1140);
    }
}

static int phy_stub_config_aneg(struct phy_device *phydev)
{
    /* Do nothing */
    return 0;
}

static int phy_stub_read_status(struct phy_device *phydev)
{
    /* Do nothing */
    return 0;
}

static struct phy_driver phy_driver_stub = {
		.phy_id		= -1, /* do not match any PHY id */
		.phy_id_mask	= 0xffffffff,
		.name		= "Vitesse PHY stub",
		.config_init	= NULL,
		.features	= 0,
		.flags		= PHY_HAS_INTERRUPT,
		.config_aneg	= &phy_stub_config_aneg,
		.read_status	= &phy_stub_read_status,
		.probe		= NULL,
		.driver		= {.owner= THIS_MODULE, },
};

static int seville_phy_init(struct seville_port_info *info, int ports_nr)
{
    int rc;

    /* Register stub PHY driver */
    if ((rc = phy_driver_register(&phy_driver_stub))) {
        pr_err(DEVICE_NAME" Cannot register PHY driver\n");
        info->seville_phy_drv_stub = NULL;
        goto __err_ret;
    }

    info->seville_phy_drv_stub = &phy_driver_stub;

    /* create char device region */
    if ((rc = alloc_chrdev_region(&info->seville_phy_dev, 0, ports_nr,
                                  "l2sw_phy")))
           goto __err_phy_alloc_chrdev_region;

    info->seville_phy_class = class_create(THIS_MODULE, "l2sw_phy");
    if (IS_ERR(info->seville_phy_class)) {
        rc = PTR_ERR(info->seville_phy_class);
        goto __err_phy_class_create;
    }

    INIT_LIST_HEAD(&info->port_list.list);

    return 0;

__err_phy_class_create:
    info->seville_phy_class = NULL;
    unregister_chrdev_region(info->seville_phy_dev, ports_nr);
__err_phy_alloc_chrdev_region:
    phy_driver_unregister(&phy_driver_stub);
    info->seville_phy_drv_stub = NULL;
__err_ret:
    return rc;
}

static void seville_phy_close(struct seville_port_info *info, int ports_nr)
{
    if (info->seville_phy_class)
        class_destroy(info->seville_phy_class);
    info->seville_phy_class = NULL;

    unregister_chrdev_region(info->seville_phy_dev, ports_nr);

    if (info->seville_phy_drv_stub)
        phy_driver_unregister(info->seville_phy_drv_stub);
    info->seville_phy_drv_stub = NULL;
}

static int seville_probe(struct platform_device *pdev)
{
    struct uio_seville *priv;
    struct uio_info *info;
    void __iomem *remap;
    struct resource *remap_res;
    struct device_node *child;
    const char *port_status;
    struct seville_port_list *tmp_port;
    struct list_head *pos, *aux;
    int sz, ret;
    const void *prop;

    priv = kzalloc(sizeof(struct uio_seville), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;
    info = &priv->uio;
    info->priv = priv;
    priv->mac_addr = NULL;
    priv->npi_dev = NULL;
    if (seville_of_io_remap(pdev, info, 0) == NULL) {
        pr_err(DEVICE_NAME" failed to map seville registers\n");
        ret = ENODEV;
        goto __out_err_seville_remap;
    }

    info->name = "Seville Switch";
    info->version = "1.0.0";
#if defined(CONFIG_OF_IRQ)
    info->irq = of_irq_to_resource(pdev->dev.of_node, 0, NULL);
#endif
    info->handler = seville_handler;
    info->irqcontrol = seville_irqcontrol;
    info->open = seville_open;
    info->release = seville_release;

    spin_lock_init(&priv->lock);
    priv->flags = 0; /* interrupt is enabled in MPICH to begin with */
    priv->pdev = pdev;
    platform_set_drvdata(pdev, priv);

    /* enable cache line support */
    remap_res = request_mem_region(T1040_SCFG_ESGMIISELCR, sizeof(u32),
            info->name);
    if (remap_res)
        remap = ioremap(remap_res->start, resource_size(remap_res));
    else
        /* WARN: some other driver might hold the register.
         * We should use an API to clear/set our bits
         */
        remap = ioremap(T1040_SCFG_ESGMIISELCR, sizeof(u32));

    if (remap) {
        iowrite32(ioread32(remap) & ~T1040_SCFG_ESGMIISELCR_ENA, remap);
        iowrite32(ioread32(remap) | T1040_SCFG_ESGMIISELCR_GMIISEL, remap);

        /* we no longer need access to this register */
        iounmap(remap);
    }
    if (remap_res)
        release_mem_region(T1040_SCFG_ESGMIISELCR, sizeof(u32));

    /* Disable interrupt */
    iowrite32(0, VTSS_DEVCPU_QS_REMAP_INTR_ENABLE);

    if (uio_register_device(&pdev->dev, info)) {
        pr_err(DEVICE_NAME" failed to register the uio device\n");
        ret = -ENODEV;
        goto __out_err_seville_register;
    }

    dev_info(&pdev->dev, "Found %s, UIO device - IRQ %ld, id 0x%08x.\n", info->name, info->irq, ioread32(VTSS_DEVCPU_GCB_CHIP_REGS_CHIP_ID));

    if (!(priv->npi_dev = kzalloc(sizeof(*priv->npi_dev), GFP_KERNEL))) {
        pr_err(DEVICE_NAME" out of memory\n");
        ret = -ENOMEM;
        goto __out_err_npi_alloc;
    }

    /* Init char device for injection and extraction of control frames */
    if (dev_npi_init(priv->npi_dev, info))
        pr_warn(DEVICE_NAME" Failed to initialize npi char device\n");

    /* get L2switch MAC address from device tree */
    priv->mac_addr = of_get_mac_address(pdev->dev.of_node);
    if (!priv->mac_addr) {
        pr_warn(DEVICE_NAME" MAC address not found\n");
    } else {
        /* Add sysfs entry for MAC address */
        if (device_create_file(&pdev->dev, &dev_attr_mac_address))
            pr_warn(DEVICE_NAME" Could not add sysfs entry for l2switch MAC address\n");
    }

    /* Register stub PHY driver */
    if ((ret = seville_phy_init(&priv->port_info, SEVILLE_PORTS_NR_MAX)))
        goto __out_err_phy_init;

    /* Parse port nodes */
    for_each_child_of_node(pdev->dev.of_node, child)
        if (of_device_is_compatible(child, "vitesse-9953-port")) {
            port_status = of_get_property(child, "status", NULL);

            /* port may be disabled */
            if (port_status && strcmp(port_status, "disabled") == 0)
                continue;

            prop = of_get_property(child, "port-index", &sz);
            if (!prop || sz < sizeof(u32)) {
                pr_err(DEVICE_NAME" port-index not specified - required parameter\n");
                ret = -ENODEV;
                goto __out_err_seville_port_node;
            }
            tmp_port = devm_kzalloc(&pdev->dev, sizeof(*tmp_port),
                            GFP_KERNEL);
            if (unlikely(tmp_port == NULL)) {
                pr_err(DEVICE_NAME" out of memory\n");
                ret = -ENOMEM;
                goto __out_err_seville_port_node;
            }

            tmp_port->port_idx = be32_to_cpup(prop);
            if ((ret = seville_phy_create(child, &priv->port_info, tmp_port,
                                  &pdev->dev.kobj))) {
                devm_kfree(&pdev->dev, tmp_port);
                goto __out_err_seville_port_node;
            }
            list_add_tail(&tmp_port->list, &priv->port_info.port_list.list);

        } else if (of_device_is_compatible(child, "vitesse-9953-mdio"))
                vsc9953_lynx_init(child, info);

    return 0;

__out_err_seville_port_node:
    list_for_each_safe(pos, aux, &priv->port_info.port_list.list) {
        tmp_port = list_entry(pos, struct seville_port_list, list);

        seville_phy_destroy(&priv->port_info, tmp_port, &pdev->dev.kobj);
        list_del(pos);
        devm_kfree(&pdev->dev, tmp_port);
    }

    seville_phy_close(&priv->port_info, SEVILLE_PORTS_NR_MAX);
__out_err_phy_init:
    device_remove_file(&pdev->dev, &dev_attr_mac_address);
    if (priv->npi_dev) {
        dev_npi_cleanup(priv->npi_dev);
        kfree(priv->npi_dev);
    }
__out_err_npi_alloc:
    uio_unregister_device(info);
__out_err_seville_register:
    iounmap(info->mem[0].internal_addr);
    iowrite32(0, VTSS_DEVCPU_QS_REMAP_INTR_ENABLE);
__out_err_seville_remap:
    kfree(priv);
    pr_err(DEVICE_NAME": Driver probe error\n");
    return ret;
}

static int seville_remove(struct platform_device *pdev)
{
    struct uio_info *info;
    struct uio_seville *priv;
    struct list_head *pos, *aux;
    struct seville_port_list *tmp_port;

    info = platform_get_drvdata(pdev);

    if (!info)
        return -EINVAL;

    priv = info->priv;
    if (!priv)
        return -EINVAL;

    /* free net-devices */
    list_for_each_safe(pos, aux, &priv->port_info.port_list.list) {
        tmp_port = list_entry(pos, struct seville_port_list, list);

        seville_phy_destroy(&priv->port_info, tmp_port, &pdev->dev.kobj);
        list_del(pos);
        devm_kfree(&pdev->dev, tmp_port);
    }

    /* Unregister PHY stub driver */
    seville_phy_close(&priv->port_info, SEVILLE_PORTS_NR_MAX);
    platform_set_drvdata(pdev, NULL);

    device_remove_file(&pdev->dev, &dev_attr_mac_address);

    if (priv->npi_dev) {
        dev_npi_cleanup(priv->npi_dev);
        kfree(priv->npi_dev);
    }

    /* Disable interrupt */
    iowrite32(0, VTSS_DEVCPU_QS_REMAP_INTR_ENABLE);
    uio_unregister_device(info);
    if (info->mem[0].internal_addr)
        iounmap(info->mem[0].internal_addr);
    kfree(priv);

    return 0;
}

static struct of_device_id seville_of_match[] = {
	{
		.compatible = "vitesse-9953",
	},
	{}
};

MODULE_DEVICE_TABLE(of, seville_of_match);

static struct platform_driver seville_driver = {
    .driver = {
        .owner = THIS_MODULE,
        .name = DEVICE_NAME,
        .of_match_table = seville_of_match,
    },
    .probe = seville_probe,
    .remove = seville_remove,
};

static int __init seville_init_module(void)
{
    int ret;

    ret = platform_driver_register(&seville_driver);
    if (unlikely(ret < 0))
        pr_warn(": %s:%hu:%s(): platform_driver_register() = %d\n",
                __FILE__, __LINE__, __func__, ret);

    return ret;
}

static void __exit seville_exit_module(void)
{
    platform_driver_unregister(&seville_driver);
}

module_init(seville_init_module);
module_exit(seville_exit_module);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Lars Povlsen <lpovlsen@vitesse.com>");
