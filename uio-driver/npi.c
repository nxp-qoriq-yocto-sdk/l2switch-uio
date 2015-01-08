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

enum status_word {
	RX_STATUS_WORD_DATA,
	RX_STATUS_WORD_EOF_0,
	RX_STATUS_WORD_EOF_1,
	RX_STATUS_WORD_EOF_2,
	RX_STATUS_WORD_EOF_3,
	RX_STATUS_WORD_TRUNCATE,
	RX_STATUS_WORD_INVALID,
	RX_STATUS_WORD_ESCAPE,
	RX_STATUS_WORD_DATA_NOT_READY,
	RX_STATUS_WORD_NONE
};

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

/* used to return the size of an entire chunk of data
 * and the reason why the chunk is terminated
 */
static enum status_word rx_frame_get_next_chunk_sz(u32 *data, size_t max_len,
        size_t *chunk_len)
{
    *chunk_len = 0;

    /* increase chunk size while we have data */
    while (likely((*chunk_len < max_len && (data[*chunk_len] &
            CONTROL_FRAME_EOF_MASK) != CONTROL_FRAME_EOF)))
        (*chunk_len)++;

    /* if we reached the maximum allowed size for our chunk,
     * return by notifying that we are in the middle of a frame
     */
    if (*chunk_len == max_len)
        return RX_STATUS_WORD_DATA;

    switch (data[*chunk_len]) {
    case CONTROL_FRAME_DATA_NOT_READY:
        return RX_STATUS_WORD_DATA_NOT_READY;
    case CONTROL_FRAME_TRUNCATE:
        return RX_STATUS_WORD_TRUNCATE;
    case CONTROL_FRAME_ESCAPE:
        return RX_STATUS_WORD_ESCAPE;
    case CONTROL_FRAME_INVALID:
        return RX_STATUS_WORD_INVALID;
    default:
        /* we reached the end of a frame */
        return RX_STATUS_WORD_EOF_0 + (data[*chunk_len] - CONTROL_FRAME_EOF);
    }
}

static ssize_t do_control_frame_extr_dev(struct npi_device *priv,
        char __user *buff, size_t len)
{
    struct uio_info *info;
    enum status_word word_rc;
    u32 *frame;
    size_t chunk_size, total_chunk_size, begin, end, copy_bytes_nr,
        bytes_nr;
    ssize_t frame_size, rc;
    int cache_line_number, i;

    if (!priv)
        return -EINVAL;

    info = priv->info;
    if (!info)
        return -EINVAL;

    chunk_size = 0;
    frame_size = 0;
    total_chunk_size = 0;
    cache_line_number = -1;
    copy_bytes_nr = 0;

    spin_lock(&priv->rx_lock);
    frame = &priv->leftover_word[priv->leftover_begin];
    begin = 0;
    end = priv->leftover_end - priv->leftover_begin;

    rc = 0;
    do {
        if (likely(end > begin)) {
            word_rc = rx_frame_get_next_chunk_sz(&frame[begin], end - begin,
                    &chunk_size);

            /* Calculate the total number of valid bytes */
            total_chunk_size = begin + chunk_size;
        } else {
            word_rc = RX_STATUS_WORD_DATA;
            chunk_size = 0;
            total_chunk_size = end;
        }

        /* Reached the end of a frame chunk */

        bytes_nr = total_chunk_size * sizeof(u32);
        if (word_rc >= RX_STATUS_WORD_EOF_0 &&
                word_rc <= RX_STATUS_WORD_EOF_3) {
            if (unlikely(bytes_nr))
                bytes_nr -= word_rc - RX_STATUS_WORD_EOF_0;
            else
                frame_size -= word_rc - RX_STATUS_WORD_EOF_0;
        }

        /* if the user's buffer is smaller, truncate the frame */
        copy_bytes_nr = (len - (size_t)frame_size < bytes_nr ?
                len - (size_t)frame_size : bytes_nr);

        switch (word_rc) {
        case RX_STATUS_WORD_TRUNCATE:
        case RX_STATUS_WORD_INVALID:
        case RX_STATUS_WORD_EOF_0:
        case RX_STATUS_WORD_EOF_1:
        case RX_STATUS_WORD_EOF_2:
        case RX_STATUS_WORD_EOF_3:
            /* EOF found; Copy remaining bytes to userspace */
            if (unlikely(copy_to_user(&buff[frame_size], (u8*)frame,
                    copy_bytes_nr))) {
                rc = -EFAULT;
                break;
            }
            frame_size += copy_bytes_nr;
            total_chunk_size = 0;
            rc = frame_size;

            if (cache_line_number == -1) {
                /* The whole frame was found in leftovers */
                priv->leftover_begin += chunk_size + 1;
                spin_unlock(&priv->rx_lock);
                return rc;
            }
            priv->leftover_begin = 0;
            priv->leftover_end = 0;

            /* Save remaining bytes locked in cache */
            memcpy(&priv->leftover_word[priv->leftover_end],
                    &frame[begin + chunk_size + 1],
                    (end - (begin + chunk_size + 1)) * sizeof(u32));
            priv->leftover_end += end - (begin + chunk_size + 1);

            /* copy the extra cache line in leftovers */
            frame = priv->extraction_queue_fifo + (((cache_line_number + 1) %
                    (FIFO_REMAPPER_SIZE / SMP_CACHE_BYTES)) * SMP_CACHE_BYTES);
            memcpy(&priv->leftover_word[priv->leftover_end],
                    frame, SMP_CACHE_BYTES);
            priv->leftover_end += SMP_CACHE_BYTES / sizeof(u32);

            break;
        case RX_STATUS_WORD_DATA_NOT_READY:
            /* Packet data not ready detected
             * when attempting to read
             */

            /* copy current chunk */
            if (unlikely(copy_to_user(&buff[frame_size], (u8*)frame,
                    copy_bytes_nr))) {
                rc = -EFAULT;
                break;
            }
            frame_size += copy_bytes_nr;
            frame += total_chunk_size + 1;

            /* prepare for the next chunk */
            begin = begin + chunk_size + 1 - (total_chunk_size + 1);
            end -= total_chunk_size + 1;

            /* if we are still reading from leftovers, we need
             * to increase the beginning of the chunk
             */
            if (cache_line_number == -1)
                priv->leftover_begin += chunk_size + 1;

            total_chunk_size = 0;

            break;
        case RX_STATUS_WORD_DATA:
            /* didn't reach EOF yet; prepare the next chunk */
            if (cache_line_number == -1) {
                /* copy chunk from leftovers */
                if (unlikely(copy_to_user(&buff[frame_size], (u8*)frame,
                        copy_bytes_nr))) {
                    rc = -EFAULT;
                    break;
                }

                frame_size += copy_bytes_nr;

                /* leftovers are cleared; we need to start
                 * reading packet data from FIFO
                 */
                priv->leftover_begin = 0;
                priv->leftover_end = 0;

                /* we must not be preempted while we have
                 * L1 cache lines locked on a core
                 */
                preempt_disable();

                /* load first 64B from extraction FIFO and
                 * lock them into L1 cache
                 */
                cache_line_load_and_lock(priv->extraction_queue_fifo);
                cache_line_number = 0;

                frame = priv->extraction_queue_fifo;
                begin = begin + chunk_size - end;
                end = SMP_CACHE_BYTES / sizeof(u32);
                total_chunk_size = 0;

                /* get an extra cache of data */

                /* before we get another cache line, check if
                 * we reached the end of the remapper
                 */
                cache_line_load_and_lock(priv->extraction_queue_fifo +
                        (((cache_line_number + 1) %
                        (FIFO_REMAPPER_SIZE / SMP_CACHE_BYTES))
                        * SMP_CACHE_BYTES));
                break;
            }

            if (unlikely(cache_line_number == 0 && !bytes_nr && !frame_size)) {
                /* we are not in the middle of a frame and no data is pending,
                 * so the size of the returned frame is 0
                 */

                /* set rc to != 0 to exit while */
                rc = 1;
                break;
            }

            /* prepare for the next FIFO cache line */
            cache_line_number = (cache_line_number + 1) %
                    (FIFO_REMAPPER_SIZE /
                    SMP_CACHE_BYTES);

            /* if we reached the end of the remapper,
             * start from beginning
             */
            if (unlikely(!cache_line_number)) {
                /* copy current chunk */
                if (unlikely(copy_to_user(&buff[frame_size], (u8*)frame,
                        copy_bytes_nr))) {
                    rc = -EFAULT;
                    break;
                }
                frame_size += copy_bytes_nr;

                /* release last cache line */
                cache_line_unlock(priv->extraction_queue_fifo +
                        (((FIFO_REMAPPER_SIZE / SMP_CACHE_BYTES) - 1)
                        * SMP_CACHE_BYTES));

                frame = priv->extraction_queue_fifo;
                begin = begin + chunk_size - total_chunk_size;
                end = SMP_CACHE_BYTES / sizeof(u32);
                total_chunk_size = 0;
            } else {
                begin += chunk_size;
                end += SMP_CACHE_BYTES / sizeof(u32);
            }

            /* get an extra cache line of data */
            if (unlikely(cache_line_number + 1 == FIFO_REMAPPER_SIZE /
                    SMP_CACHE_BYTES)) {
                /* if we reached the end of the remapper,
                 * write current packet data to userspace
                 * frist
                 */
                if (unlikely(copy_to_user(&buff[frame_size], (u8*)frame,
                        copy_bytes_nr))) {
                    rc = -EFAULT;
                    break;
                }
                frame_size += copy_bytes_nr;
                frame += total_chunk_size;
                begin -= total_chunk_size;
                end -= total_chunk_size;
                total_chunk_size = 0;

                /* Unlock all the cache lines,
                 * except the current (last) one
                 */
                for (i = 0; i < cache_line_number; i++)
                    cache_line_unlock(priv->extraction_queue_fifo +
                            (i * SMP_CACHE_BYTES));
            }

            cache_line_load_and_lock(priv->extraction_queue_fifo +
                    (((cache_line_number + 1) %
                    (FIFO_REMAPPER_SIZE / SMP_CACHE_BYTES))
                    * SMP_CACHE_BYTES));
            break;
        case RX_STATUS_WORD_ESCAPE:
            /* Chunk is interrupted by an escape character;
             * copy valid bytes
             */
            if (unlikely(copy_to_user(&buff[frame_size], (u8*)frame,
                    copy_bytes_nr))) {
                rc = -EFAULT;
                break;
            }
            frame_size += copy_bytes_nr;
            frame += total_chunk_size + 1;

            /* jump over first word since we know it's data */
            begin = begin + chunk_size + 2 - (total_chunk_size + 1);
            end -= total_chunk_size + 1;
            if (cache_line_number == -1)
                priv->leftover_begin += chunk_size + 1;
            total_chunk_size = 0;

            break;
        default:
            /* We should never reach here */
            pr_err("Unknown CPU Rx status word\n");
            rc = -EINVAL;
        }
    } while (!rc);

    /* release all the locked cache lines */
    if (cache_line_number != -1) {
        if (unlikely(((cache_line_number + 1) %
                (FIFO_REMAPPER_SIZE / SMP_CACHE_BYTES)) == 0)) {
            /* there are only 2 cache lines to release:
             * the last and the first of the remapper
             */
            cache_line_unlock(priv->extraction_queue_fifo +
                    (cache_line_number * SMP_CACHE_BYTES));
            cache_line_unlock(priv->extraction_queue_fifo);
        } else {
            for (i = 0; i <= cache_line_number + 1; i++)
                cache_line_unlock(priv->extraction_queue_fifo +
                        (i * SMP_CACHE_BYTES));
        }

        /* all cache lines have been released,
         * it's safe to be preempted
         */
        preempt_enable();
    }
    spin_unlock(&priv->rx_lock);
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

    spin_lock(&priv->tx_lock);

    if (unlikely(ioread32(VTSS_DEVCPU_QS_INJ_INJ_STATUS) &
            VTSS_M_DEVCPU_QS_INJ_INJ_STATUS_INJ_IN_PROGRESS)) {
        pr_err("FIFO is busy reciving another frame\n");
        rc = -EBUSY;
        goto __out_release_lock;
    }

    /* wait for available memory in CPU queues */
    while(ioread32(VTSS_DEVCPU_QS_INJ_INJ_STATUS) &
            VTSS_M_DEVCPU_QS_INJ_INJ_STATUS_WMARK_REACHED)
        ;

    /* get frame from userspace */
    buff = kmalloc(len, GFP_KERNEL);
    if (unlikely(!buff)) {
        rc = -ENOMEM;
        goto __out_release_lock;
    }

    not_copied = copy_from_user(buff, buff_usr, len);
    if (unlikely(not_copied)) {
        rc = -EFAULT;
        goto __out_free;
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

__out_free:
    kfree(buff);
__out_release_lock:
    spin_unlock(&priv->tx_lock);
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
    spin_lock(&priv->read_thread_lock);
    if (priv->read_thread) {
        spin_unlock(&priv->read_thread_lock);
        return -EBUSY;
    }

    /* get task_struct of the current thread */
    priv->read_thread = current;

    spin_unlock(&priv->read_thread_lock);

    info = priv->info;

    spin_lock(&priv->rx_lock);
    priv->leftover_end = priv->leftover_begin = 0;
    memset(priv->leftover_word, 0, sizeof(priv->leftover_word));
    spin_unlock(&priv->rx_lock);

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
    spin_lock(&priv->rx_lock);
    priv->leftover_begin = priv->leftover_end = 0;
    spin_unlock(&priv->rx_lock);

    spin_lock(&priv->read_thread_lock);
    priv->read_thread = NULL;
    spin_unlock(&priv->read_thread_lock);

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

    /* interrupt might still be pending, so we should try to clear it;
     * if control frames arrived in the meantime, the interrupt
     * will not be cleared
     */
    SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_IDENT, GR0);

    /* if there are fames pending, read them */
    if (unlikely(ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1))
        return do_control_frame_extr_dev(priv, buff, len);

    /* if we do not have a frame pending,
     * enable interrupt and wait for one */
    if (!(ioread32(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE) & GR0))
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

    spin_lock(&priv->rx_lock);

    /* first skip words that are not data */
    while (priv->leftover_begin < priv->leftover_end &&
                (priv->leftover_word[priv->leftover_begin] &
                        CONTROL_FRAME_EOF_MASK) == CONTROL_FRAME_EOF &&
                        priv->leftover_word[priv->leftover_begin] !=
                                CONTROL_FRAME_ESCAPE)
        priv->leftover_begin++;
    /* we might already read a frame from the previous read */
    if (priv->leftover_begin < priv->leftover_end) {
        spin_unlock(&priv->rx_lock);
        return POLLIN | POLLRDNORM;
    }
    spin_unlock(&priv->rx_lock);

    /* interrupt might be pending, so we should try to clear it */
    SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_IDENT, GR0);

    /* If we have data pending, return */
    if (ioread32(VTSS_DEVCPU_QS_XTR_XTR_DATA_PRESENT) & 1)
        return POLLIN | POLLRDNORM;

    /* Enable interrupt to assure we have data ready */
    if (!(ioread32(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE) & GR0))
        SET_REG(VTSS_DEVCPU_QS_REMAP_INTR_ENABLE, GR0);

    poll_wait(file, &priv->npi_read_q, wait);

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

    npi_dev->read_thread = NULL;

    init_waitqueue_head(&npi_dev->npi_read_q);
    spin_lock_init(&npi_dev->read_thread_lock);
    spin_lock_init(&npi_dev->rx_lock);
    spin_lock_init(&npi_dev->tx_lock);

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
