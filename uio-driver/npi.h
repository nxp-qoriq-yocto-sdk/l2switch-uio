/*
 * NPI interface driver
 *
 * Copyright (c) 2014 Freescale Semiconductor, Inc.
 * Author: Codrin Ciubotariu
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#ifndef NPI_H_
#define NPI_H_

#include <linux/uio_driver.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/sched.h>
#include <linux/cdev.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>

#define VTSS_IOREG(t,o) (info->mem[0].internal_addr + VTSS_IOADDR(t,o))
#include "vtss_seville_regs_devcpu_gcb.h"
#include "vtss_seville_regs_devcpu_qs.h"

#define SET_REG(reg, mask)	iowrite32(ioread32((reg)) | (mask), (reg))
#define CLR_REG(reg, mask)	iowrite32(ioread32((reg)) & ~(mask), (reg))

/* Extraction group 0 mask */
#define GR0 0x40

/**
 * struct npi_device - description of character device used for NPI interface
 * @info:			pointer back to the uio device that
 * 				initializes the char device;
 * @extraction_queue_fifo:	remapper used for extracting control frames;
 * @leftover_word:		array used to hold the extra words that might be
 * 				present after we reach the end of a
 * 				control frame;
 * @leftover_start:		start of useful data contained
 * 				within the leftover;
 * @leftover_end:		end of useful data contained
 * 				within the leftover;
 * @npi_cdev:			char device for NPI interface;
 * @npi_nr:			assigned number for NPI char device;
 * @npi_class:			class created for NPI char device;
 * @read_thread:		the thread that opened the NPI char device
 * 				must be remembered to be able to wake it up from
 * 				the seville interrupt handler when control
 * 				frames are available;
 */
struct npi_device {
    struct uio_info *info;
    void __iomem *extraction_queue_fifo;
    u32 leftover_word[(2 * SMP_CACHE_BYTES)/sizeof(u32)];
    size_t leftover_start;
    size_t leftover_end;

    /* char device attributes */
    struct cdev npi_cdev;
    dev_t npi_nr;
    struct class *npi_class;

    struct task_struct *read_thread;
};

int dev_npi_init(struct npi_device *npi_dev, struct uio_info *info);
int dev_npi_cleanup(struct npi_device *npi_dev);

#endif /* NPI_H_ */
