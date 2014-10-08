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

/* Register used for remapper bypassing */
#define T1040_SCFG_ESGMIISELCR		0xffe0fc020

/* Bit masks used to for address remapper scfg_esgmiiselcr */
#define T1040_SCFG_ESGMIISELCR_ENA		0x20
#define T1040_SCFG_ESGMIISELCR_GMIISEL		0x80

#include "npi.h"

/* Vitesse VSC8514 PHY_ID */
#define PHY_ID_VSC8514			0x00070670

/* Vitesse VSC8514 main registers */
#define PHY_ID_REG1			0x02
#define PHY_ID_REG2			0x03

/* Vitesse VSC8514 Extended PHY Control Register 1 */
#define PHY_EXT_PAGE_ACCESS		0x1f
#define PHY_EXT_PAGE_ACCESS_EXTENDED3	0x3
#define PHY_EXT_PAGE_ACCESS_GENERAL	0x10

/* Vitesse VSC8514 control register */
#define MIIM_VSC8514_GENERAL18		0x12
#define MIIM_VSC8514_GENERAL19		0x13
#define MIIM_VSC8514_GENERAL23		0x17
#define MIIM_VSC8514_MAC_SERDES_CON	0x10
#define MIIM_VSC8514_MAC_SERDES_ANEG	0x80

/* Vitesse VSC8514 general purpose register 18 */
#define MIIM_VSC8514_18G_QSGMII		0x80e0
#define MIIM_VSC8514_18G_CMDSTAT	0x8000
#define MIIM_VSC8514_18G_CMDERR		0x4000

/* Timeout used to wait while MIIM controller becomes idle */
#define MIIM_TIMEOUT		1000000

#define DEVICE_NAME "seville"

/* Private structure for external ports located in a struct net_device */
struct seville_port_private {
    u32 port_idx;

    /* Register number used by sysfs */
    u32 regnum;

    struct phy_device	*phy_dev;
};

struct seville_port_list {
	struct list_head	list;
	struct net_device	*ndev;
};

struct uio_seville {
    struct uio_info uio;
    /* Private data */
    spinlock_t lock;
    unsigned long flags;
    const u8 *mac_addr;
    struct platform_device *pdev;
    struct seville_port_list port_list;
    struct npi_device *npi_dev;
};

/* Prototypes for creating and destroying sysfs entries */
static int phy_sysfs_create(struct device *dev);
static void phy_sysfs_destroy(struct device *dev);

static ssize_t show_phy_reg(struct device *dev,
		struct device_attribute *attr, char *buf)
{
    unsigned n = 0;
    struct phy_device *phydev;
    struct seville_port_private *port_priv;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    port_priv = netdev_priv(phydev->attached_dev);
    n = snprintf(buf, PAGE_SIZE, "%u\n", port_priv->regnum);

    return n;
}

static ssize_t store_phy_reg(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
    struct phy_device *phydev;
    struct seville_port_private *port_priv;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    port_priv = netdev_priv(phydev->attached_dev);
    sscanf(buf, "%u", &port_priv->regnum);

    return count;
}

/* PHY register address */
static DEVICE_ATTR(phy_reg, S_IRUGO|S_IWUSR, &show_phy_reg, &store_phy_reg);

static ssize_t show_phy_val(struct device *dev,
		struct device_attribute *attr, char *buf)
{
    unsigned  n = 0;
    int val;
    struct phy_device *phydev;
    struct seville_port_private *port_priv;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    port_priv = netdev_priv(phydev->attached_dev);
    val = phy_read(phydev, port_priv->regnum);
    n = snprintf(buf, PAGE_SIZE, "%d\n", val);

    return n;
}

static ssize_t store_phy_val(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
    u16 val;
    struct phy_device *phydev;
    struct seville_port_private *port_priv;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    sscanf(buf, "%hu", &val);
    port_priv = netdev_priv(phydev->attached_dev);
    phy_write(phydev, port_priv->regnum, val);

    return count;
}

/* PHY register value */
static DEVICE_ATTR(phy_val, S_IRUGO|S_IWUSR, &show_phy_val, &store_phy_val);

static int phy_sysfs_create(struct device *dev)
{
    struct phy_device *phydev;
    struct seville_port_private *port_priv;

    if (dev == NULL)
        return -EINVAL;

    phydev = to_phy_device(dev);

    /* Default: read MII_BMSR status register */
    port_priv = netdev_priv(phydev->attached_dev);
    port_priv->regnum = 1;

    /* Create register address entry */
    if (device_create_file(dev, &dev_attr_phy_reg) != 0)
        return -EIO;

    /* Create register value entry */
    if (device_create_file(dev, &dev_attr_phy_val) != 0)
        return -EIO;

    return 0;
}

static void phy_sysfs_destroy(struct device *dev)
{
    if (WARN_ON(dev == NULL))
        return;

    device_remove_file(dev, &dev_attr_phy_reg);
    device_remove_file(dev, &dev_attr_phy_val);
}

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
    if (!ioread32(VTSS_DEVCPU_QS_REMAP_INTR_IDENT)) {
        /* not our interrupt */
        handled = 0;
    } else {
        struct uio_seville *priv = info->priv;

        /* clear interrupt pending */
        SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_IDENT, GR0);
        if (unlikely(!(ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1))) {
            /* no data is pending */
            return IRQ_RETVAL(IRQ_HANDLED);
        }

        /* Disable interrupt */
        CLR_REG(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE, GR0);

        if (likely(priv->npi_dev->read_thread))
            wake_up_interruptible(&priv->npi_dev->npi_read_q);

        handled = IRQ_HANDLED;
    }
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
            pr_devel("%s: %d: Mapped %llx size %lu to %p\n", DEVICE_NAME,
                     index, info->mem[index].addr, info->mem[index].size, addr);
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

static int phy_probe(struct device *dev)
{
    struct phy_device *phydev = to_phy_device(dev);
    u16 val;
    u32 phy_id;
    int aux;
    int timeout = 1000000;

    /* Check if PHY is VSC8514 */
    aux = phy_read(phydev, PHY_ID_REG1);

    /* PHY might not be present */
    if (aux < 0)
	    goto __add_sysfs;
    phy_id = (aux & 0xFFFF) << 16;

    aux = phy_read(phydev, PHY_ID_REG2);

    /* PHY might not be present */
    if (aux < 0)
        goto __add_sysfs;
    phy_id |= aux & 0xFFFF;

    /* Skip initialization if it's not VSC8514 */
    if (phy_id != PHY_ID_VSC8514)
        goto __add_sysfs;

    /* configure register to access 19G */
    phy_write(phydev, PHY_EXT_PAGE_ACCESS, PHY_EXT_PAGE_ACCESS_GENERAL);

    val = phy_read(phydev, MIIM_VSC8514_GENERAL19);

    /* set bit 15:14 to '01' for QSGMII mode */
    val = (val & 0x3fff) | (1 << 14);
    phy_write(phydev, MIIM_VSC8514_GENERAL19, val);

    /* Enable 4 ports MAC QSGMII */
    phy_write(phydev, MIIM_VSC8514_GENERAL18, MIIM_VSC8514_18G_QSGMII);

    /* When bit 15 is cleared the command has completed */
    do {
        val = phy_read(phydev, MIIM_VSC8514_GENERAL18);
        if (val & MIIM_VSC8514_18G_CMDERR) {
            pr_warn(DEVICE_NAME" PHY %x error condition detected\n",
                    phydev->addr);
            break;
        }
    } while ((val & MIIM_VSC8514_18G_CMDSTAT) && --timeout);

    if (timeout == 0) {
        pr_err("PHY 8514 config failed\n");
        return -EBUSY;
    }

    phy_write(phydev, PHY_EXT_PAGE_ACCESS, 0);
    /* configure register to access 23 */
    val = phy_read(phydev, MIIM_VSC8514_GENERAL23);
    /* set bits 10:8 to '000' */
    val = (val & 0xf8ff);
    phy_write(phydev, MIIM_VSC8514_GENERAL23, val);

    /* Enable Serdes Auto-negotiation */
    phy_write(phydev, PHY_EXT_PAGE_ACCESS, PHY_EXT_PAGE_ACCESS_EXTENDED3);
    val = phy_read(phydev, MIIM_VSC8514_MAC_SERDES_CON);
    val = val | MIIM_VSC8514_MAC_SERDES_ANEG;
    phy_write(phydev, MIIM_VSC8514_MAC_SERDES_CON, val);

    phy_write(phydev, PHY_EXT_PAGE_ACCESS, 0);

__add_sysfs:
    /* Create sysfs entries for regs */
    if (phy_sysfs_create(dev) != 0) {
        dev_err(dev, "ERROR:%s:%d:Unable to create PHY sysfs entries",
                __FILE__,
                __LINE__);
        return -EIO;
    }

    return 0;
}

static int phy_remove(struct device *dev)
{
    /* Remove sysfs entries */
    phy_sysfs_destroy(dev);

    return 0;
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

static int bind_phy_device(struct device_node *port_node, struct seville_port_list *port)
{
    struct net_device *port_netdev_stub;
    struct device_node *phy_node;
    struct phy_device *phy_dev;
    struct seville_port_private *port_priv;

    phy_node = of_parse_phandle(port_node, "phy-handle", 0);

    /* this may be a fixed link */
    if (!phy_node)
        goto out;

    phy_dev = of_phy_find_device(phy_node);
    if (!phy_dev) {
        pr_err(DEVICE_NAME" no PHY device found\n");
        goto out;
    }

    if (phy_dev->attached_dev) {
        pr_err(DEVICE_NAME" PHY device in use, cannot bind to PHY\n");
        goto out;
    }

    if (phy_dev->drv)
        device_release_driver(&phy_dev->dev);

    if (phy_dev->drv) {
        pr_err(DEVICE_NAME" unbind PHY device failed\n");
        goto out;
    }

    phy_dev->drv = &phy_driver_stub;
    phy_dev->dev.driver = &phy_driver_stub.driver;

    if (phy_driver_stub.probe && phy_driver_stub.probe(phy_dev) < 0 ) {
        pr_err(DEVICE_NAME" PHY driver stub probe error\n");
        goto out;
    }

    if (device_bind_driver(&phy_dev->dev)) {
        pr_err(DEVICE_NAME" PHY driver stub bind error\n");
        goto out;
    }

    port_netdev_stub = alloc_etherdev(sizeof(struct seville_port_private));
    if (!port_netdev_stub)
        goto out;

    /* claim PHY as our own, don't let others attach to it */
    phy_dev->attached_dev = port_netdev_stub;
    port->ndev = port_netdev_stub;
    port_priv = netdev_priv(port_netdev_stub);
    port_priv->phy_dev = phy_dev;

out:
    return 0;
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
    struct seville_port_private *port_priv;
    struct list_head *pos, *aux;
    int driver_register = 0;
    char *sysfs_phy_name = NULL;
    int sz;
    const void *prop;

    priv = kzalloc(sizeof(struct uio_seville), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;
    info = &priv->uio;
    info->priv = priv;
    priv->mac_addr = NULL;
    priv->npi_dev = NULL;
    if (seville_of_io_remap(pdev, info, 0) == NULL) {
        goto out_error;
    }

    info->name = "Seville Switch";
    info->version = "1.0.0";
#if defined(CONFIG_OF_IRQ)
    info->irq = of_irq_to_resource(pdev->dev.of_node, 0, NULL);
#endif
    info->handler = seville_handler;
    info->irqcontrol = seville_irqcontrol;

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
        /* some other driver might hold the register */
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

    if (uio_register_device(&pdev->dev, info))
        goto out_error;

    dev_info(&pdev->dev, "Found %s, UIO device - IRQ %ld, id 0x%08x.\n", info->name, info->irq, ioread32(VTSS_DEVCPU_GCB_CHIP_REGS_CHIP_ID));

    if (!(priv->npi_dev = kzalloc(sizeof(*priv->npi_dev), GFP_KERNEL)))
          return -ENOMEM;
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
    if ((driver_register = phy_driver_register(&phy_driver_stub))) {
        pr_err(DEVICE_NAME" Cannot register PHY driver\n");
        goto out_error;
    }

    INIT_LIST_HEAD(&priv->port_list.list);
    sysfs_phy_name = kzalloc(sizeof("phy_") + 3, GFP_KERNEL);
    if (!sysfs_phy_name) {
        pr_err(DEVICE_NAME" out of memory\n");
        goto out_error;
    }

    /* Parse port nodes */
    for_each_child_of_node(pdev->dev.of_node, child)
        if (of_device_is_compatible(child, "vitesse-9953-port")) {
            port_status = of_get_property(child, "status", NULL);

            /* port may be disabled */
            if (port_status && strcmp(port_status, "disabled") == 0)
                continue;

            prop = of_get_property(child, "port-index", &sz);
            if (!prop || sz < sizeof(port_priv->port_idx)) {
                pr_err(DEVICE_NAME" port-index not specified - required parameter\n");
                goto out_error;
            }
            tmp_port = devm_kzalloc(&pdev->dev, sizeof(*tmp_port),
                            GFP_KERNEL);
            if (unlikely(tmp_port == NULL)) {
                pr_err(DEVICE_NAME" out of memory\n");
                goto out_error;
            }

            tmp_port->ndev = NULL;
            bind_phy_device(child, tmp_port);

            list_add_tail(&tmp_port->list, &priv->port_list.list);
            if (!tmp_port->ndev)
                continue;
            port_priv = netdev_priv(tmp_port->ndev);

            /* Add PHY sysfs entries */
            phy_probe(&port_priv->phy_dev->dev);

            /* Create symbolic link in UIO sysfs to PHY sysfs entries */
            port_priv->port_idx = be32_to_cpup(prop);
            sprintf(sysfs_phy_name, "phy_%u", port_priv->port_idx);
            if (sysfs_create_link(&pdev->dev.kobj, &port_priv->phy_dev->dev.kobj,
                            sysfs_phy_name))
                pr_warn(DEVICE_NAME" couldn't create symbolic link %s\n",
                            sysfs_phy_name);
        } else if (of_device_is_compatible(child, "vitesse-9953-mdio"))
                vsc9953_lynx_init(child, info);

    kfree(sysfs_phy_name);
    return 0;

out_error:
    list_for_each_safe(pos, aux, &priv->port_list.list) {
        tmp_port = list_entry(pos, struct seville_port_list, list);
        if (!tmp_port->ndev)
            continue;

        port_priv = netdev_priv(tmp_port->ndev);

        sprintf(sysfs_phy_name, "phy_%u", port_priv->port_idx);
        sysfs_remove_link(&pdev->dev.kobj, sysfs_phy_name);

        phy_remove(&port_priv->phy_dev->dev);
        port_priv->phy_dev->attached_dev = NULL;
        free_netdev(tmp_port->ndev);
        tmp_port->ndev = NULL;
        list_del(pos);
        devm_kfree(&pdev->dev, tmp_port);
    }

    if (sysfs_phy_name) kfree(sysfs_phy_name);
    if (driver_register) phy_driver_unregister(&phy_driver_stub);
    device_remove_file(&pdev->dev, &dev_attr_mac_address);
    dev_npi_cleanup(priv->npi_dev);
    if (priv->npi_dev) kfree(priv->npi_dev);
    uio_unregister_device(info);
    if( info->mem[0].internal_addr) iounmap(info->mem[0].internal_addr);
    iowrite32(0, VTSS_DEVCPU_QS_REMAP_INTR_ENABLE);
    kfree(info);
    pr_err("%s: Driver probe error\n", DEVICE_NAME);
    return -ENODEV;
}


static int seville_remove(struct platform_device *pdev)
{
    struct uio_info *info = platform_get_drvdata(pdev);
    struct uio_seville *priv = info->priv;
    struct list_head *pos, *aux;
    struct seville_port_list *tmp_port;
    struct seville_port_private *port_priv;
    char *sysfs_phy_name;

    if (!info) {
        return 0;
    }

    sysfs_phy_name = kzalloc(sizeof("phy_") + 3, GFP_KERNEL);
    if (!sysfs_phy_name)
        return 0;

    /* free net-devices */
    list_for_each_safe(pos, aux, &priv->port_list.list) {
        tmp_port = list_entry(pos, struct seville_port_list, list);
        if (!tmp_port->ndev)
            continue;
        port_priv = netdev_priv(tmp_port->ndev);

        /* Remove PHY sysfs entries */
        phy_remove(&port_priv->phy_dev->dev);

        /* Remove symbolic link in UIO sysfs to PHY sysfs entries */
        sprintf(sysfs_phy_name, "phy_%u", port_priv->port_idx);
        sysfs_remove_link(&pdev->dev.kobj, sysfs_phy_name);

        port_priv->phy_dev->attached_dev = NULL;
        free_netdev(tmp_port->ndev);
        tmp_port->ndev = NULL;
        list_del(pos);
        devm_kfree(&pdev->dev, tmp_port);
    }
    kfree(sysfs_phy_name);

    /* Unregister PHY stub driver */
    phy_driver_unregister(&phy_driver_stub);
    platform_set_drvdata(pdev, NULL);

    device_remove_file(&pdev->dev, &dev_attr_mac_address);
    dev_npi_cleanup(priv->npi_dev);
    if (priv->npi_dev) kfree(priv->npi_dev);

    /* Disable interrupt */
    iowrite32(0, VTSS_DEVCPU_QS_REMAP_INTR_ENABLE);

    uio_unregister_device(info);

    if (info->mem[0].internal_addr) iounmap(info->mem[0].internal_addr);
    kfree(info->priv);

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
