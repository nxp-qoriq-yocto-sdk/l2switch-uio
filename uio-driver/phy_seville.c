/*
 * Seville user-space PHY driver.
 *
 * Copyright (C) 2014 Vitesse Semiconductor Inc.
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc.
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
#include <linux/of_irq.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/poll.h>

#include "phy_seville.h"

/* Vitesse VSC8514 PHY_ID */
#define PHY_ID_VSC8514			0x00070670

/* Vitesse VSC8514 main registers */
#define PHY_ID_REG1			0x02
#define PHY_ID_REG2			0x03
#define PHY_INTR_MASK			0x19
#define PHY_INTR_STAT			0x1a

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
    mutex_lock(&port_list->phy_lock);
    val = phy_read(phydev, port_list->regnum);
    mutex_unlock(&port_list->phy_lock);
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

    mutex_lock(&port_list->phy_lock);
    phy_write(phydev, port_list->regnum, val);
    mutex_unlock(&port_list->phy_lock);

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

static int seville_phy_main_reg_rd(struct phy_device *phydev, u32 regnum)
{
    struct seville_port_list *port_list;
    int ext_page_access;
    int val;

    if (!phydev)
        return -EINVAL;

    port_list = phydev->priv;

    if (!port_list)
        return -EINVAL;

    mutex_lock(&port_list->phy_lock);

    /* save PHY Extended Page Access register value */
    ext_page_access = phy_read(phydev, PHY_EXT_PAGE_ACCESS);
    if (unlikely(ext_page_access < 0)) {
        val = ext_page_access;
        pr_err("%s: PHY read error on Extended Page Access reg\n",
               port_list->sysfs_phy_name);
        goto __return_unlock;
    }
    if (unlikely(ext_page_access)) {
        val = phy_write(phydev, PHY_EXT_PAGE_ACCESS, 0);
        if (unlikely(val < 0)) {
            pr_err("%s: PHY write error on Extended Page Access reg\n",
                   port_list->sysfs_phy_name);
            goto __return_unlock;
        }
    }

    val = phy_read(phydev, regnum);

    /* restore PHY Extended Page Access register if necessary */
    if (unlikely(ext_page_access))
        if (unlikely(phy_write(phydev, PHY_EXT_PAGE_ACCESS, ext_page_access)
                     < 0))
            pr_err("%s: PHY write failed to restore Extended Page Access reg\n",
                   port_list->sysfs_phy_name);

__return_unlock:
    mutex_unlock(&port_list->phy_lock);

    return val;
}

static int seville_phy_main_reg_wr(struct phy_device *phydev, u32 regnum,
                                   u16 val)
{
    struct seville_port_list *port_list;
    int ext_page_access;
    int rc;

    if (!phydev)
        return -EINVAL;

    port_list = phydev->priv;

    if (!port_list)
        return -EINVAL;

    mutex_lock(&port_list->phy_lock);

    /* save PHY Extended Page Access register value */
    ext_page_access = phy_read(phydev, PHY_EXT_PAGE_ACCESS);
    if (unlikely(ext_page_access < 0)) {
        rc = ext_page_access;
        pr_err("%s: PHY read error on Extended Page Access register\n",
               port_list->sysfs_phy_name);
        goto __return_unlock;
    }

    if (unlikely(ext_page_access)) {
        rc = phy_write(phydev, PHY_EXT_PAGE_ACCESS, 0);
        if (unlikely(rc < 0)) {
            pr_err("%s: PHY write error on Extended Page Access register\n",
                   port_list->sysfs_phy_name);
            goto __return_unlock;
        }
    }

    rc = phy_write(phydev, regnum, val);

    /* restore PHY Extended Page Access register if necessary */
    if (unlikely(ext_page_access))
        if (unlikely(phy_write(phydev, PHY_EXT_PAGE_ACCESS, ext_page_access))
                               < 0)
            pr_err("%s: PHY write failed to restore Extended Page Access reg\n",
                   port_list->sysfs_phy_name);

__return_unlock:
    mutex_unlock(&port_list->phy_lock);

    return rc;
}

static void seville_phy_change(struct work_struct *work)
{
    int intr_stat;
    struct phy_device *phydev =
             container_of(work, struct phy_device, phy_queue);
    struct seville_port_list *port_list = phydev->priv;
    unsigned long flags;

    /* get PHY intr status */
    intr_stat = seville_phy_main_reg_rd(port_list->phy_dev, PHY_INTR_STAT);

    /* enable interrupt line ASAP */
    enable_irq(port_list->phy_irq);

    if (unlikely(intr_stat < 0))
        pr_err("%s: error when trying to read PHY intr status\n",
               port_list->sysfs_phy_name);

    if (intr_stat > 0) {
        /* Increment number of IRQs received for this PHY */
        atomic_inc(&port_list->irq_count);

        /* set interrupt status bit */
        spin_lock_irqsave(&port_list->phy_flags_lock, flags);
        set_bit(PHY_FLAGS_IRQ_STATUS, &port_list->flags);
        spin_unlock_irqrestore(&port_list->phy_flags_lock, flags);

        /* wake up the user-space sleeping thread */
        wake_up_interruptible(&port_list->phy_read_q);
    }
}

static irqreturn_t seville_phy_cdev_handler(int irq, void *dev_id)
{
    struct seville_port_list *port_list;
    int handled;

    if (unlikely(!dev_id)) {
        handled = IRQ_NONE;
        goto __return;
    }

    port_list = dev_id;

    if (unlikely(irq != port_list->phy_irq)) {
        handled = IRQ_NONE;
        goto __return;
    }

    disable_irq_nosync(irq);

    queue_work(system_power_efficient_wq, &port_list->phy_dev->phy_queue);

    handled = IRQ_HANDLED;
__return:
    return IRQ_RETVAL(handled);
}

static int seville_phy_cdev_open(struct inode *inode, struct file *file)
{
    struct seville_port_list *port_list;
    unsigned long flags;
    int rc;

    if (!inode || !file)
        return -EINVAL;

    port_list = container_of(inode->i_cdev, struct seville_port_list, phy_cdev);

    if (!port_list)
        return -EINVAL;

    /* only one process is allowed to open the PHY char device */
    spin_lock_irqsave(&port_list->phy_flags_lock, flags);
    if (test_and_set_bit(PHY_FLAGS_IN_USE, &port_list->flags)) {
        rc = -EBUSY;
        spin_unlock_irqrestore(&port_list->phy_flags_lock, flags);
        goto __return;
    }
    spin_unlock_irqrestore(&port_list->phy_flags_lock, flags);

    /* clear IRQ count number */
    atomic_set(&port_list->irq_count, 0);

    file->private_data = port_list;

    /* Enable PHY interrupt */
    if ((rc = seville_phy_main_reg_wr(port_list->phy_dev, PHY_INTR_MASK,
                                      0xF000)) < 0)
        pr_warn("%s: Failed to set intr mask - %d\n",
                port_list->sysfs_phy_name, rc);

    rc = 0;

__return:
    return rc;
}

static int seville_phy_cdev_release(struct inode *inode, struct file *file)
{
    struct seville_port_list *port_list;
    unsigned long flags;
    int rc;

    if (!inode || !file)
        return -EINVAL;

    port_list = container_of(inode->i_cdev, struct seville_port_list, phy_cdev);

    if (!port_list)
        return -EINVAL;

    /* Only one process is able to close a previously opened PHY char device */
    spin_lock_irqsave(&port_list->phy_flags_lock, flags);
    if (!test_and_clear_bit(PHY_FLAGS_IN_USE, &port_list->flags))
        rc = -EINVAL;
    spin_unlock_irqrestore(&port_list->phy_flags_lock, flags);

    /* Mask PHY interrupt */
    if (seville_phy_main_reg_wr(port_list->phy_dev, PHY_INTR_MASK, 0) < 0)
        pr_warn("%s: Failed to clear intr mask\n",
                port_list->sysfs_phy_name);

    /* clear IRQ count number */
    atomic_set(&port_list->irq_count, 0);

    file->private_data = NULL;

    return 0;
}

static ssize_t seville_phy_cdev_read(struct file *file, char __user *buff,
                                     size_t len, loff_t *offset)
{
    struct seville_port_list *port_list;
    unsigned long flags;
    int intr_stat;
    s32 count;
    ssize_t rc = 0;

    if (!file || !buff || len != sizeof(s32))
        return -EINVAL;

    port_list = file->private_data;
    if (!port_list)
        return -EINVAL;

    /* if there is no PHY device present, return error */
    if (!port_list->phy_dev)
        return -EINVAL;

    /* check Interrupt Status from flags raised */
    spin_lock_irqsave(&port_list->phy_flags_lock, flags);
    intr_stat = test_and_clear_bit(PHY_FLAGS_IRQ_STATUS, &port_list->flags);
    spin_unlock_irqrestore(&port_list->phy_flags_lock, flags);
    if (likely(intr_stat))
        goto __return_wakeup;

    /* sleep until interrupt arrives */
    wait_event_interruptible(port_list->phy_read_q,
                             test_bit(PHY_FLAGS_IRQ_STATUS, &port_list->flags));

    /* clear IRQ status flag */
    spin_lock(&port_list->phy_flags_lock);
    clear_bit(PHY_FLAGS_IRQ_STATUS, &port_list->flags);
    spin_unlock(&port_list->phy_flags_lock);

__return_wakeup:
    count = atomic_read(&port_list->irq_count);
    if (unlikely(copy_to_user(buff, &count, sizeof(count)))) {
        rc = -EFAULT;
    } else {
        rc = sizeof(count);
    }

    return rc;
}

static ssize_t seville_phy_cdev_write(struct file *file,
                                      const char __user *buff,
                                      size_t len, loff_t *offset)
{
    /* Nothing to do for now */
    return 0;
}

static unsigned int seville_phy_cdev_poll(struct file *file, poll_table *wait)
{
    struct seville_port_list *port_list;
    unsigned long flags;
    int intr_stat;

    if (!file)
        return POLLERR;

    port_list = file->private_data;
    if (!port_list)
        return POLLERR;

    /* check if IRQ was already raised */
    spin_lock_irqsave(&port_list->phy_flags_lock, flags);
    intr_stat = test_bit(PHY_FLAGS_IRQ_STATUS, &port_list->flags);
    spin_unlock_irqrestore(&port_list->phy_flags_lock, flags);
    if (likely(intr_stat))
        return POLLIN | POLLRDNORM;

    poll_wait(file, &port_list->phy_read_q, wait);

    return 0;
}

static struct file_operations seville_phy_fops = {
                .open = &seville_phy_cdev_open,
                .release = &seville_phy_cdev_release,
                .read = &seville_phy_cdev_read,
                .write = &seville_phy_cdev_write,
                .poll = &seville_phy_cdev_poll,
};

int seville_phy_create(struct device_node *port_node,
                       struct seville_port_info *port_info,
                       struct seville_port_list *port_list,
                       struct kobject *seville_kobj)
{
    struct device *cdev;
    struct device_node *phy_node;
    dev_t devno;
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

    spin_lock_init(&port_list->phy_flags_lock);
    init_waitqueue_head(&port_list->phy_read_q);
    mutex_init(&port_list->phy_lock);
    port_list->flags = 0;
    atomic_set(&port_list->irq_count, 0);
    INIT_WORK(&port_list->phy_dev->phy_queue, seville_phy_change);

    /* Mask PHY interrupt */
    if (seville_phy_main_reg_wr(port_list->phy_dev, PHY_INTR_MASK, 0) < 0)
        pr_warn("%s: Failed to clear Intr mask\n", port_list->sysfs_phy_name);

    /* Add PHY sysfs entries */
    phy_probe(&port_list->phy_dev->dev);

    /* Create symbolic link in UIO sysfs to PHY sysfs entries */
    if (sysfs_create_link(seville_kobj, &port_list->phy_dev->dev.kobj,
                          port_list->sysfs_phy_name))
         pr_warn("%s: couldn't create symbolic link\n",
                 port_list->sysfs_phy_name);

    port_list->phy_irq = irq_of_parse_and_map(phy_node, 0);
    if (!port_list->phy_irq) {
        pr_warn("%s: Failed to get irq number - %u", port_list->sysfs_phy_name,
               port_list->phy_irq);
        return 0;
    } else {
        pr_info("%s: shared IRQ %u\n", port_list->sysfs_phy_name,
                port_list->phy_irq);
        rc = request_irq(port_list->phy_irq, &seville_phy_cdev_handler,
                         IRQF_SHARED, port_list->sysfs_phy_name, port_list);
        if (rc) {
            pr_warn("%s: Failed to request irq %u, error %d\n",
                    port_list->sysfs_phy_name, port_list->phy_irq, rc);
            port_list->phy_irq = 0;
            return 0;
        }
    }

    if (!port_info->seville_phy_class) {
        pr_warn("%s: no PHY class found\n", port_list->sysfs_phy_name);
        rc = 0;
        goto __out_free;
    }

    devno = MKDEV(MAJOR(port_info->seville_phy_dev), port_list->port_idx);

    cdev = device_create(port_info->seville_phy_class, NULL,
                         devno, NULL, "l2sw_%s", port_list->sysfs_phy_name);
    if (IS_ERR(cdev)) {
        rc = PTR_ERR(cdev);
        pr_warn("%s: Failed to create device", port_list->sysfs_phy_name);
        goto __out_free;
    }

    cdev_init(&port_list->phy_cdev, &seville_phy_fops);

    if ((rc = cdev_add(&port_list->phy_cdev, devno, 1))) {
        pr_warn("%s: Failed to add cdev", port_list->sysfs_phy_name);
        goto __out_destroy;
    }

    return 0;

__out_destroy:
    device_destroy(port_info->seville_phy_class, devno);
    port_info->seville_phy_class = NULL;
__out_free:
    if (port_list->sysfs_phy_name) {
        kfree(port_list->sysfs_phy_name);
        port_list->sysfs_phy_name = NULL;
    }
__out_return:
    return rc;
}

int seville_phy_destroy(struct seville_port_info *port_info,
                        struct seville_port_list *port_list,
                        struct kobject *seville_kobj)
{
    dev_t devno;
    int rc = 0;

    if (!port_info || !port_list || !seville_kobj) {
	    rc = -EINVAL;
	    goto _out_return;
    }

    /* Mask PHY interrupt */
    if (port_list->phy_dev)
        if (seville_phy_main_reg_wr(port_list->phy_dev, PHY_INTR_MASK, 0) < 0)
            pr_warn("%s: Failed to clear intr mask\n",
                    port_list->sysfs_phy_name);

    if (port_list->phy_irq) {
        free_irq(port_list->phy_irq, port_list);
    }

    /* nothing to do if there is no PHY device attached */
    if (port_list->phy_dev) {
        flush_work(&port_list->phy_dev->phy_queue);

        if (port_list->phy_irq) {
            cdev_del(&port_list->phy_cdev);

            devno = MKDEV(MAJOR(port_info->seville_phy_dev),
                          port_list->port_idx);
            if (port_info->seville_phy_class)
                device_destroy(port_info->seville_phy_class, devno);

            port_list->phy_irq = 0;
        }
    }

    /* Remove symbolic link in UIO sysfs to PHY sysfs entries */
    sysfs_remove_link(seville_kobj, port_list->sysfs_phy_name);

    /* clear IRQ count number */
    atomic_set(&port_list->irq_count, 0);

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
