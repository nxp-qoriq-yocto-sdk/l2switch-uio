/*
 * Seville user-space PHY interface driver
 *
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#ifndef PHY_SEVILLE_H_
#define PHY_SEVILLE_H_

#include <linux/io.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/spinlock.h>

/* enums used for PHY's flag bits */
enum {
    PHY_FLAGS_IN_USE = 0,
    PHY_FLAGS_IRQ_STATUS
};

/* Private structure for L2 Switch ports */
struct seville_port_list {
    struct list_head    list;
    u32                 port_idx;

    /* Register number used by sysfs */
    u32                 regnum;

    char                *sysfs_phy_name;
    struct phy_device   *phy_dev;
    struct mutex        phy_lock;
    spinlock_t          phy_flags_lock;
    unsigned long       flags;
    struct cdev         phy_cdev;
    unsigned int        phy_irq;
    wait_queue_head_t   phy_read_q;
    atomic_t            irq_count;
};

struct seville_port_info {
    struct seville_port_list port_list;
    struct phy_driver *seville_phy_drv_stub;
    dev_t seville_phy_dev;
    struct class *seville_phy_class;
};

int seville_phy_create(struct device_node *port_node,
                       struct seville_port_info *port_priv,
                       struct seville_port_list *port_list,
                       struct kobject *seville_kobj);

int seville_phy_destroy(struct seville_port_info *port_priv,
                        struct seville_port_list *port_list,
                        struct kobject *seville_kobj);


#endif /* PHY_SEVILLE_H_ */
