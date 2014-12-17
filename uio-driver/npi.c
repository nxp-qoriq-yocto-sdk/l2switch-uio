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

#include "npi.h"

#include <linux/poll.h>
#include <linux/slab.h>

#define FLUSH_TIMEOUT	100000

/* Defines used for EOF special values */
#define CONTROL_FRAME_EOF_MASK			0xFFFFFFF8
#define CONTROL_FRAME_EOF			0x80000000
#define CONTROL_FRAME_EOF_UNUSED_BYTES_MASK	0x00000003
#define CONTROL_FRAME_TRUNCATE		0x80000004
#define CONTROL_FRAME_INVALID		0x80000005
#define CONTROL_FRAME_ESCAPE		0x80000006
#define CONTROL_FRAME_DATA_NOT_READY	0x80000007

#define FIFO_REMAPPER_SIZE	4096

#define MAX_FRAME_SIZE		16384

static inline void cache_line_load_and_lock(void __iomem *addr)
{
    asm volatile (
            "dcbz 0, %[addr]\n\t"
            "dcbtls 2, 0, %[addr]\n\t"
            "dcbf 0, %[addr]\n\t"
            "dcbtstls 0, 0, %[addr]"
            : /* no output */ : [addr]"r"(addr));
}

static inline void cache_line_unlock(void __iomem *addr)
{
    asm volatile (
            "dcblc 0, 0, %[addr]\n\t"
            "dcblc 2, 0, %[addr]\n\t"
            : /* no output */ : [addr]"r"(addr));
}

static ssize_t do_control_frame_extr_dev(struct npi_device *priv,
		char __user *buff, size_t len)
{
    struct uio_info *info = priv->info;
    size_t i;
    int unwritten_bytes;
    int eof;
    u32 *extr_cache;
    int cache_line_number;
    ssize_t frame_size;
    ssize_t chunk_size;
    size_t len_bk = len;
    ssize_t copied_bytes;
    ssize_t unused_bytes;
    int data_next;

    eof = frame_size = data_next = 0;

    /* skip EOFs from beginning of leftover words */
    while (priv->leftover_begin < priv->leftover_end &&
                (priv->leftover_word[priv->leftover_begin] &
                        CONTROL_FRAME_EOF_MASK) == CONTROL_FRAME_EOF &&
                        priv->leftover_word[priv->leftover_begin] !=
                                CONTROL_FRAME_ESCAPE)
        priv->leftover_begin++;

    /* if we found an escape EOF, remember that next word is data */
    if (unlikely(priv->leftover_begin < priv->leftover_end &&
            priv->leftover_word[priv->leftover_begin] ==
            CONTROL_FRAME_ESCAPE)) {
        data_next = 1;
        priv->leftover_begin++;
    }

    for (i = priv->leftover_begin; i < priv->leftover_end; i++) {
        /* If we have a word with data, just keep on going */
        if (likely((priv->leftover_word[i] & CONTROL_FRAME_EOF_MASK) !=
                CONTROL_FRAME_EOF))
            continue;

        /* a previous escape EOF assures us
         * that this word contains packet data */
        if (unlikely(data_next)) {
            data_next = 0;
            continue;
        }

        switch(priv->leftover_word[i]) {
        case CONTROL_FRAME_ESCAPE:
            /* send to userspace current packet words */
            unwritten_bytes = copy_to_user(&buff[frame_size],
                    &priv->leftover_word[priv->leftover_begin],
                    min(len, (i - priv->leftover_begin) * sizeof(u32)));
            if (likely(unwritten_bytes >= 0)) {
                copied_bytes = min(len, (i - priv->leftover_begin) *
                        sizeof(u32)) - (ssize_t)unwritten_bytes;
                frame_size += copied_bytes;
                len -= copied_bytes;
            }
            priv->leftover_begin = i + 1;

            /* next word is data */
            data_next = 1;

            break;
        case CONTROL_FRAME_TRUNCATE:
        case CONTROL_FRAME_INVALID:
            /* discard truncated or invalid frames */
            frame_size = 0;
            priv->leftover_begin = i + 1;
            len = len_bk;

            break;
        default:
            /* EOF specifying number of unused bytes or data not ready */
            unwritten_bytes = copy_to_user(&buff[frame_size],
                    &priv->leftover_word[priv->leftover_begin],
                    min(len, (i - priv->leftover_begin) * sizeof(u32)));
            if (likely(unwritten_bytes >= 0)) {
                copied_bytes = min(len, (i - priv->leftover_begin) *
                                    sizeof(u32)) - (ssize_t)unwritten_bytes;

                /* remove unused bytes from last word */
                if (likely(priv->leftover_word[i] !=
                        CONTROL_FRAME_DATA_NOT_READY)) {
                    unused_bytes = priv->leftover_word[i] &
                                    CONTROL_FRAME_EOF_UNUSED_BYTES_MASK;
                    if (likely(unused_bytes > (ssize_t)unwritten_bytes &&
                            len >= ((i - priv->leftover_begin) * sizeof(u32)
                                    - (size_t)unused_bytes)))
                        copied_bytes -= unused_bytes - (ssize_t)unwritten_bytes;
                }
                frame_size += copied_bytes;
                len -= copied_bytes;
            }
            priv->leftover_begin = i + 1;

            /* We may find an entire frame in leftovers */
            if (likely(frame_size > 0))
                return frame_size;
        }
    }

    /* copy remaining data words from leftover */
    unwritten_bytes = copy_to_user(&buff[frame_size],
            &priv->leftover_word[priv->leftover_begin],
            min(len, (i - priv->leftover_begin) * sizeof(u32)));
    if (likely(unwritten_bytes >= 0)) {
        copied_bytes = min(len, (i - priv->leftover_begin) * sizeof(u32))
                        - (ssize_t)unwritten_bytes;
        frame_size += copied_bytes;
        len -= copied_bytes;
    }

    /* Clear leftovers */
    priv->leftover_end = priv->leftover_begin = 0;

    extr_cache = priv->extraction_queue_fifo;
    chunk_size = cache_line_number = 0;

    /* clear interrupt before reading */
    if (!(ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1))
        SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_IDENT, GR0);

    /* we must not be preempted while we have
     * L1 cache lines locked on a core */
    preempt_disable();

    /* load first 64B from extraction fifo and lock them into L1 cache */
    cache_line_load_and_lock(priv->extraction_queue_fifo);

    do {
        /* before we get another cache line, check if
         * we reached the end of the remapper */
        if (unlikely(cache_line_number + 1 ==
                FIFO_REMAPPER_SIZE/SMP_CACHE_BYTES)) {
            /* write current packet data to userspace */
            unwritten_bytes = copy_to_user(&buff[frame_size], extr_cache,
                    min(len, chunk_size * sizeof(u32)));
            if (likely(unwritten_bytes >= 0)) {
                copied_bytes = min(len, chunk_size * sizeof(u32)) -
                        (ssize_t)unwritten_bytes;
                frame_size += copied_bytes;
                len -= copied_bytes;
            }
            extr_cache += chunk_size;
            chunk_size = 0;

            /* release cache lines, since we sent
             * the packet data from them */
            for (i = 0; i < cache_line_number - 1; i++)
                cache_line_unlock(priv->extraction_queue_fifo +
                        (i * SMP_CACHE_BYTES));
        }

        /* get an extra cache line of data */
        cache_line_load_and_lock(priv->extraction_queue_fifo +
                ((cache_line_number + 1) %
                        (FIFO_REMAPPER_SIZE/SMP_CACHE_BYTES)) *
                    SMP_CACHE_BYTES);

        /* parse the cache line for EOF words */
        for (i = 0; i < SMP_CACHE_BYTES/sizeof(u32); i++) {
            if (likely((extr_cache[chunk_size] & CONTROL_FRAME_EOF_MASK) !=
                    CONTROL_FRAME_EOF)) {
                chunk_size++;
                continue;
            }

            if (unlikely(data_next)) {
                data_next = 0;
                chunk_size++;
                continue;
            }

            switch(extr_cache[chunk_size]) {
            case CONTROL_FRAME_ESCAPE:
                unwritten_bytes = copy_to_user(&buff[frame_size], extr_cache,
                        min(len, chunk_size * sizeof(u32)));
                if (likely(unwritten_bytes >= 0)) {
                    copied_bytes = min(len, chunk_size * sizeof(u32)) -
                            (ssize_t)unwritten_bytes;
                    frame_size += copied_bytes;
                    len -= copied_bytes;
                }
                extr_cache += chunk_size + 1;
                chunk_size = 0;

                /* next word is data, so we skip it */
                data_next = 1;

                break;
            case CONTROL_FRAME_TRUNCATE:
            case CONTROL_FRAME_INVALID:
                extr_cache += chunk_size + 1;
                chunk_size = frame_size = 0;
                len = len_bk;

            break;
            default:
                /* we might receive EOF, even if we are not
                 * in the middle of a frame */
                if (unlikely(!chunk_size && !frame_size)) {
                    extr_cache++;
                    continue;
                }

                unwritten_bytes = copy_to_user(&buff[frame_size], extr_cache,
                        min(len, chunk_size * sizeof(u32)));
                if (likely(unwritten_bytes >= 0)) {
                    copied_bytes = min(len, chunk_size * sizeof(u32)) -
                            (ssize_t)unwritten_bytes;

                    /* remove unused bytes from last word */
                    if (likely(extr_cache[chunk_size] !=
                            CONTROL_FRAME_DATA_NOT_READY)) {
                        unused_bytes = extr_cache[chunk_size] &
                                CONTROL_FRAME_EOF_UNUSED_BYTES_MASK;
                        if (likely(unused_bytes > (ssize_t)unwritten_bytes &&
                                len >= (chunk_size * sizeof(u32) -
                                        unused_bytes)))
                            copied_bytes -= unused_bytes -
                                                (ssize_t)unwritten_bytes;
                    }
                    frame_size += copied_bytes;
                    len -= copied_bytes;
                }

                extr_cache += chunk_size + 1;
                chunk_size = 0;

                /* a frame has been extracted */
                eof = 1;

                i++;
                /* copy remaining words in leftover */
                if (unlikely(i == SMP_CACHE_BYTES/sizeof(u32)))
                    break;

                memcpy(priv->leftover_word, extr_cache,
                        (SMP_CACHE_BYTES/sizeof(u32) - i) * sizeof(u32));
                priv->leftover_begin = 0;
                priv->leftover_end = SMP_CACHE_BYTES/sizeof(u32) - i;
                break;
            }
            if (unlikely(eof))
                break;
        }

        /* prepare for the next cache line */
        cache_line_number = (cache_line_number + 1) %
                (FIFO_REMAPPER_SIZE/SMP_CACHE_BYTES);

        if (unlikely(!cache_line_number)) {
            /* we start from the beginning of the remapper;
             * copy to userspace what we have until now*/
            unwritten_bytes = copy_to_user(&buff[frame_size], extr_cache,
                    min(len, chunk_size * sizeof(u32)));
            if (likely(unwritten_bytes >= 0)) {
                copied_bytes = min(len, chunk_size * sizeof(u32)) -
                        (ssize_t)unwritten_bytes;
                frame_size += copied_bytes;
                len -= copied_bytes;
            }
            extr_cache = priv->extraction_queue_fifo;
            chunk_size = 0;

            /* free last cache line */
            cache_line_unlock(priv->extraction_queue_fifo +
                    FIFO_REMAPPER_SIZE - SMP_CACHE_BYTES);
        }
    }while (!eof && (chunk_size || frame_size));

    /* remember the the extra loaded words from cache line*/
    memcpy(&priv->leftover_word[priv->leftover_end],
            priv->extraction_queue_fifo + (cache_line_number * SMP_CACHE_BYTES),
            SMP_CACHE_BYTES);
    priv->leftover_end += SMP_CACHE_BYTES/sizeof(u32);

    /* release all locked cache lines */
    for (i = 0; i <= cache_line_number; i++)
        cache_line_unlock(priv->extraction_queue_fifo + (i * SMP_CACHE_BYTES));

    /* all cache lines have been released, it's safe to be preempted */
    preempt_enable();

    return frame_size;
}

static ssize_t do_control_frame_inj_dev(struct npi_device *priv,
		const char __user *buff_usr, const size_t len)
{
    struct uio_info *info;
    u32 val;
    size_t i;
    ssize_t rc;
    unsigned long not_copied;
    char *buff;

    info = priv->info;

    if (unlikely(ioread32(VTSS_DEVCPU_QS_INJ_INJ_STATUS) &
            VTSS_M_DEVCPU_QS_INJ_INJ_STATUS_INJ_IN_PROGRESS)) {
        pr_err("FIFO is busy reciving another frame\n");
        return -EBUSY;
    }

    /* wait for available memory in CPU queues */
    while(ioread32(VTSS_DEVCPU_QS_INJ_INJ_STATUS) &
            VTSS_M_DEVCPU_QS_INJ_INJ_STATUS_WMARK_REACHED)
        ;

    /* get frame from userspace */
    buff = kmalloc(len, GFP_KERNEL);
    if (unlikely(!buff))
        return -ENOMEM;

    not_copied = copy_from_user(buff, buff_usr, len);
    if (unlikely(not_copied)) {
        rc = -EFAULT;
        goto __out_return;
    }

    /* next 32b are start-of-frame */
    SET_REG(VTSS_DEVCPU_QS_INJ_INJ_CTRL(0), VTSS_F_DEVCPU_QS_INJ_INJ_CTRL_SOF);

    /* by running some small tests, we decided that
     * we do not need to wait for the injection fifo to be ready;
     * however, we should run more tests */
    i = 0;
    if (likely(len >= 4))
        for (; i < len - 4; i += 4) {
        iowrite32be(((buff[i] & 0xFF) << 24) + ((buff[i + 1] & 0xFF) << 16) +
                ((buff[i + 2] & 0xFF) << 8) + (buff[i + 3] & 0xFF),
            VTSS_DEVCPU_QS_INJ_INJ_WR(0));
        }

    val = 0;
    switch(len - i) {
    case 1:
        val += (buff[i] & 0xFF) << 24;
        break;
    case 2:
        val += ((buff[i] & 0xFF) << 24) +
            ((buff[i + 1] & 0xFF) << 16);
        break;
    case 3:
        val += ((buff[i] & 0xFF) << 24) +
            ((buff[i + 1] & 0xFF) << 16) +
            ((buff[i + 2] & 0xFF) << 8);
        break;
    case 4:
        val += ((buff[i] & 0xFF) << 24) +
            ((buff[i + 1] & 0xFF) << 16) +
            ((buff[i + 2] & 0xFF) << 8) +
            (buff[i + 3] & 0xFF);
        break;
    }

    iowrite32be(val, VTSS_DEVCPU_QS_INJ_INJ_WR(0));

    /* set valid bytes from last word */
    iowrite32((ioread32(VTSS_DEVCPU_QS_INJ_INJ_CTRL(0)) &
        ~VTSS_M_DEVCPU_QS_INJ_INJ_CTRL_VLD_BYTES) |
            VTSS_F_DEVCPU_QS_INJ_INJ_CTRL_VLD_BYTES((len - i) % 4) |
        VTSS_F_DEVCPU_QS_INJ_INJ_CTRL_EOF,
        VTSS_DEVCPU_QS_INJ_INJ_CTRL(0));

    /* write dummy FCS */
    iowrite32be(0, VTSS_DEVCPU_QS_INJ_INJ_WR(0));

    rc = len;

__out_return:
    kfree(buff);
    return rc;
}

static int dev_npi_open(struct inode *inode, struct file *file)
{
    struct npi_device *priv;
    struct uio_info *info;

    priv = container_of(inode->i_cdev, struct npi_device, npi_cdev);
    if (!priv)
        return -EINVAL;

    /* Only one application may open this device */
    if (priv->read_thread)
        return -EBUSY;

    info = priv->info;

    priv->leftover_end = priv->leftover_begin = 0;
    memset(priv->leftover_word, 0, sizeof(priv->leftover_word));

    /* Flush control port before registering the NPI char device */
    do {
        /* clear interrupt pending */
        SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_IDENT, GR0);
        /* start flushing */
        SET_REG(VTSS_DEVCPU_QS_XTR_XTR_FLUSH, 1);

        /* flush as long as we have frames */
        while (1 & ioread32(VTSS_DEVCPU_QS_REMAP_INTR_RAW))
            ; /* flushing data */

        /* disable flushing */
        CLR_REG(VTSS_DEVCPU_QS_XTR_XTR_FLUSH, 1);

        /* interrupt might still be pending; keep reading frames */
    }while (GR0 & ioread32(VTSS_DEVCPU_QS_REMAP_INTR_IDENT));

    /* get task_struct of the current thread */
    priv->read_thread = current;

    file->private_data = priv;

    return 0;
}

static int dev_npi_close(struct inode *inode, struct file *file)
{
    struct npi_device *priv;
    struct uio_info *info;

    priv = container_of(inode->i_cdev, struct npi_device, npi_cdev);
    if (!priv)
        return -EINVAL;

    /* clear leftovers */
    priv->leftover_begin = priv->leftover_end = 0;

    priv->read_thread = NULL;

    info = priv->info;

    /* Disable interrupt */
    iowrite32(0, VTSS_DEVCPU_QS_REMAP_INTR_ENABLE);

    return 0;
}

/* returns one frame at a time */
static ssize_t dev_npi_read(struct file *file, char __user *buff, size_t len,
        loff_t *offset)
{
    struct npi_device *priv = file->private_data;
    struct uio_info *info;
    ssize_t size;

    if (unlikely(!priv))
        return -EINVAL;

    info = priv->info;
    if (unlikely(!info))
        return -EINVAL;

    size = do_control_frame_extr_dev(priv, buff, len);

    /* if file was opened in nonblocking mode, return */
    if (size || (file->f_flags & O_NONBLOCK))
        return size;

    /* if we do not have a frame pending,
     * enable interrupt and wait for one */
    SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE, GR0);
    wait_event_interruptible(priv->npi_read_q,
        ((ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1) != 0));

    return do_control_frame_extr_dev(priv, buff, len);
}

static ssize_t dev_npi_write(struct file *file, const char __user *buff,
        size_t len, loff_t *offset)
{
    struct npi_device *priv = (struct npi_device *)file->private_data;

    if (unlikely(!priv))
        return -EINVAL;

    return do_control_frame_inj_dev(priv, buff, len);
}

static unsigned int dev_npi_poll(struct file *file, poll_table *wait)
{
    struct npi_device *priv = (struct npi_device *)file->private_data;
    struct uio_info *info;

    if (unlikely(!priv))
        return POLLERR;

    info = priv->info;
    if (unlikely(!info))
        return POLLERR;

    /* first skip words that are not data */
    while (priv->leftover_begin < priv->leftover_end &&
                (priv->leftover_word[priv->leftover_begin] &
                        CONTROL_FRAME_EOF_MASK) == CONTROL_FRAME_EOF &&
                        priv->leftover_word[priv->leftover_begin] !=
                                CONTROL_FRAME_ESCAPE)
        priv->leftover_begin++;

     /* we might already read a frame from the previous read */
    if (priv->leftover_begin < priv->leftover_end)
        return POLLIN | POLLRDNORM;

    /* If we have data pending, return */
    if (ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1)
        return POLLIN | POLLRDNORM;

    /* Enable interrupt to assure we have data ready */
    if (!(ioread32(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE) & GR0))
        SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE, GR0);

    poll_wait(file, &priv->npi_read_q, wait);

    /* if data is now available, then we are ready to read it */
    if (ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1)
        return POLLIN | POLLRDNORM;

    return 0;
}

static struct file_operations npi_fops = {
		.open = dev_npi_open,
		.release = dev_npi_close,
		.read = dev_npi_read,
		.write = dev_npi_write,
		.poll = dev_npi_poll,
};

int dev_npi_init(struct npi_device *npi_dev, struct uio_info *info)
{
    int ret = 0;

    if (!npi_dev || !info)
        return -EINVAL;

    /* Map cacheable extraction group 0 */
    if (!(npi_dev->extraction_queue_fifo = ioremap_prot(info->mem[0].addr +
            FSL_EXTRACTION_GROUP(0), FIFO_REMAPPER_SIZE, _PAGE_GUARDED))) {
        pr_warn("NPI: Can't map CPU extraction groups\n");
        return -EINVAL;
    }

    npi_dev->info = info;

    /* create NPI char device */
    if ((ret = alloc_chrdev_region(&npi_dev->npi_nr, 0, 1, "npi")))
        goto __err_npi_alloc_chrdev_region;

    if (!(npi_dev->npi_class = class_create(THIS_MODULE, "npi"))) {
        ret = -1;
        goto __err_npi_class_create;
    }

    if (!(device_create(npi_dev->npi_class, NULL,
            npi_dev->npi_nr, NULL, "npi"))) {
        ret = -1;
        goto __err_npi_device_create;
    }

    cdev_init(&npi_dev->npi_cdev, &npi_fops);
    if ((ret = cdev_add(&npi_dev->npi_cdev, npi_dev->npi_nr, 1)))
        goto __err_npi_cdev_add;

    npi_dev->read_thread = NULL;

    init_waitqueue_head(&npi_dev->npi_read_q);

    return 0;

__err_npi_cdev_add:
    device_destroy(npi_dev->npi_class, npi_dev->npi_nr);
__err_npi_device_create:
    class_destroy(npi_dev->npi_class);
__err_npi_class_create:
    unregister_chrdev_region(npi_dev->npi_nr, 1);
__err_npi_alloc_chrdev_region:
    iounmap(npi_dev->extraction_queue_fifo);

    return ret;
}

int dev_npi_cleanup(struct npi_device *npi_dev)
{
    if (!npi_dev)
        return -EINVAL;

    cdev_del(&npi_dev->npi_cdev);
    if (npi_dev->npi_class) {
        device_destroy(npi_dev->npi_class, npi_dev->npi_nr);
        class_destroy(npi_dev->npi_class);
    }
    unregister_chrdev_region(npi_dev->npi_nr, 1);
    if (npi_dev->extraction_queue_fifo)
        iounmap(npi_dev->extraction_queue_fifo);

    return 0;
}
