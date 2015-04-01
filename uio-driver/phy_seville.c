/*
 * Seville user-space PHY driver.
 *
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#include <linux/device.h>
#include <linux/etherdevice.h>

#include <linux/of.h>
#include <linux/of_mdio.h>

#include "phy_seville.h"

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

/* Prototypes for creating and destroying sysfs entries */
static int phy_sysfs_create(struct device *dev);
static void phy_sysfs_destroy(struct device *dev);

static ssize_t show_phy_reg(struct device *dev, struct device_attribute *attr,
                            char *buf)
{
    unsigned n = 0;
    struct phy_device *phydev;
    struct seville_port_list *port_list;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    port_list = phydev->priv;
    n = snprintf(buf, PAGE_SIZE, "%u\n", port_list->regnum);

    return n;
}

static ssize_t store_phy_reg(struct device *dev, struct device_attribute *attr,
                             const char *buf, size_t count)
{
    struct phy_device *phydev;
    struct seville_port_list *port_list;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    port_list = phydev->priv;
    sscanf(buf, "%u", &port_list->regnum);

    return count;
}

/* PHY register address */
static DEVICE_ATTR(phy_reg, S_IRUGO|S_IWUSR, &show_phy_reg, &store_phy_reg);

static ssize_t show_phy_val(struct device *dev, struct device_attribute *attr,
                            char *buf)
{
    unsigned  n = 0;
    int val;
    struct phy_device *phydev;
    struct seville_port_list *port_list;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    port_list = phydev->priv;
    val = phy_read(phydev, port_list->regnum);
    n = snprintf(buf, PAGE_SIZE, "%d\n", val);

    return n;
}

static ssize_t store_phy_val(struct device *dev, struct device_attribute *attr,
                             const char *buf, size_t count)
{
    u16 val;
    struct phy_device *phydev;
    struct seville_port_list *port_list;

    if (!buf || !dev)
        return -EINVAL;

    phydev = to_phy_device(dev);
    sscanf(buf, "%hu", &val);

    port_list = phydev->priv;

    phy_write(phydev, port_list->regnum, val);

    return count;
}

/* PHY register value */
static DEVICE_ATTR(phy_val, S_IRUGO|S_IWUSR, &show_phy_val, &store_phy_val);

static int phy_sysfs_create(struct device *dev)
{
    struct phy_device *phydev;
    struct seville_port_list *port_list;

    if (dev == NULL)
        return -EINVAL;

    phydev = to_phy_device(dev);

    port_list = phydev->priv;

    /* Default: read MII_BMSR status register */
    port_list->regnum = 1;

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

static int phy_probe(struct device *dev)
{
    struct phy_device *phydev;
    u16 val;
    u32 phy_id;
    int aux;
    int timeout = 1000000;

    if (unlikely(!dev))
        return -EINVAL;

    phydev = to_phy_device(dev);

    /* port might be a fixed link */
    if (unlikely(!phydev))
        return 0;

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
            pr_warn("%s: PHY %x error condition detected\n",
                    dev->init_name, phydev->addr);
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

static int bind_phy_device(struct device_node *phy_node,
                           struct seville_port_list *port_list,
                           struct phy_driver *phy_driver_stub)
{
    struct net_device *port_netdev_stub;
    struct phy_device *phy_dev;

    if (!port_list || !phy_driver_stub)
        return -EINVAL;

    /* this may be a fixed link */
    if (!phy_node)
        goto out;

    phy_dev = of_phy_find_device(phy_node);
    if (!phy_dev) {
        pr_err("%s: no PHY device found\n", port_list->sysfs_phy_name);
        goto out;
    }

    if (phy_dev->attached_dev) {
        pr_err("%s: PHY device in use, cannot bind\n",
                port_list->sysfs_phy_name);
        goto out;
    }

    if (phy_dev->drv)
        device_release_driver(&phy_dev->dev);

    if (phy_dev->drv) {
        pr_err("%s: unbind PHY device failed\n", port_list->sysfs_phy_name);
        goto out;
    }

    phy_dev->drv = phy_driver_stub;
    phy_dev->dev.driver = &phy_driver_stub->driver;

    if (phy_driver_stub->probe && phy_driver_stub->probe(phy_dev) < 0 ) {
        pr_err("%s: PHY driver stub probe error\n", port_list->sysfs_phy_name);
        goto out;
    }

    if (device_bind_driver(&phy_dev->dev)) {
        pr_err("%s: PHY driver stub bind error\n", port_list->sysfs_phy_name);
        goto out;
    }

    port_netdev_stub = alloc_etherdev(sizeof(0));
    if (!port_netdev_stub)
        goto out;

    /* claim PHY as our own, don't let others attach to it */
    phy_dev->attached_dev = port_netdev_stub;
    phy_dev->priv = port_list;
    port_list->phy_dev = phy_dev;

out:
    return 0;
}

int seville_phy_create(struct device_node *port_node,
                       struct seville_port_info *port_info,
                       struct seville_port_list *port_list,
                       struct kobject *seville_kobj)
{
    struct device_node *phy_node;
    int rc;

    port_list->sysfs_phy_name = kmalloc(sizeof("phy_") + 3, GFP_KERNEL);
    if (!port_list->sysfs_phy_name) {
        rc = -ENOMEM;
        goto __out_return;
    }
    sprintf(port_list->sysfs_phy_name, "phy_%u", port_list->port_idx);

    phy_node = of_parse_phandle(port_node, "phy-handle", 0);

    bind_phy_device(phy_node, port_list, port_info->seville_phy_drv_stub);

    /* nothing to do if there is no PHY device found */
    if (!port_list->phy_dev) {
        rc = 0;
        goto __out_return;
    }

    /* Add PHY sysfs entries */
    phy_probe(&port_list->phy_dev->dev);

    /* Create symbolic link in UIO sysfs to PHY sysfs entries */
    if (sysfs_create_link(seville_kobj, &port_list->phy_dev->dev.kobj,
                          port_list->sysfs_phy_name))
         pr_warn("%s: couldn't create symbolic link\n",
                 port_list->sysfs_phy_name);

    return 0;

__out_return:
    return rc;
}

int seville_phy_destroy(struct seville_port_info *port_info,
                        struct seville_port_list *port_list,
                        struct kobject *seville_kobj)
{
    int rc = 0;

    if (!port_info || !port_list || !seville_kobj) {
	    rc = -EINVAL;
	    goto _out_return;
    }

    /* Remove symbolic link in UIO sysfs to PHY sysfs entries */
    sysfs_remove_link(seville_kobj, port_list->sysfs_phy_name);

    if (port_list->phy_dev) {
        /* Remove PHY sysfs entries */
        phy_remove(&port_list->phy_dev->dev);

        if (port_list->phy_dev->attached_dev) {
            free_netdev(port_list->phy_dev->attached_dev);
            port_list->phy_dev->attached_dev = NULL;
        }
    }

_out_return:
    if (port_list && port_list->sysfs_phy_name) {
        kfree(port_list->sysfs_phy_name);
        port_list->sysfs_phy_name = NULL;
    }
    return rc;
}
