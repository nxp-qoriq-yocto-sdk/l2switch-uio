#ifndef _VTSS_SEVILLE_REGS_DEVCPU_GCB_H_
#define _VTSS_SEVILLE_REGS_DEVCPU_GCB_H_

/*
 *
 * VCore-III Register Definitions
 *
 * Copyright (C) 2012 Vitesse Semiconductor Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "vtss_seville_regs_common.h"

#define VTSS_DEVCPU_GCB_CHIP_REGS_CHIP_ID    VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0x0)
#define  VTSS_F_DEVCPU_GCB_CHIP_REGS_CHIP_ID_REV_ID(x)  VTSS_ENCODE_BITFIELD(x,28,4)
#define  VTSS_M_DEVCPU_GCB_CHIP_REGS_CHIP_ID_REV_ID     VTSS_ENCODE_BITMASK(28,4)
#define  VTSS_X_DEVCPU_GCB_CHIP_REGS_CHIP_ID_REV_ID(x)  VTSS_EXTRACT_BITFIELD(x,28,4)
#define  VTSS_F_DEVCPU_GCB_CHIP_REGS_CHIP_ID_PART_ID(x)  VTSS_ENCODE_BITFIELD(x,12,16)
#define  VTSS_M_DEVCPU_GCB_CHIP_REGS_CHIP_ID_PART_ID     VTSS_ENCODE_BITMASK(12,16)
#define  VTSS_X_DEVCPU_GCB_CHIP_REGS_CHIP_ID_PART_ID(x)  VTSS_EXTRACT_BITFIELD(x,12,16)
#define  VTSS_F_DEVCPU_GCB_CHIP_REGS_CHIP_ID_MFG_ID(x)  VTSS_ENCODE_BITFIELD(x,1,11)
#define  VTSS_M_DEVCPU_GCB_CHIP_REGS_CHIP_ID_MFG_ID     VTSS_ENCODE_BITMASK(1,11)
#define  VTSS_X_DEVCPU_GCB_CHIP_REGS_CHIP_ID_MFG_ID(x)  VTSS_EXTRACT_BITFIELD(x,1,11)
#define  VTSS_F_DEVCPU_GCB_CHIP_REGS_CHIP_ID_ONE  VTSS_BIT(0)

#define VTSS_DEVCPU_GCB_CHIP_REGS_GPR        VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0x1)

#define VTSS_DEVCPU_GCB_CHIP_REGS_SOFT_RST   VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0x2)
#define  VTSS_F_DEVCPU_GCB_CHIP_REGS_SOFT_RST_SOFT_SWC_RST  VTSS_BIT(0)

#define VTSS_DEVCPU_GCB_GPIO_GPIO_OUT_SET(ri)  VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0x3 + (ri))
#define  VTSS_F_DEVCPU_GCB_GPIO_GPIO_OUT_SET_G_OUT_SET(x)  VTSS_ENCODE_BITFIELD(x,0,6)
#define  VTSS_M_DEVCPU_GCB_GPIO_GPIO_OUT_SET_G_OUT_SET     VTSS_ENCODE_BITMASK(0,6)
#define  VTSS_X_DEVCPU_GCB_GPIO_GPIO_OUT_SET_G_OUT_SET(x)  VTSS_EXTRACT_BITFIELD(x,0,6)

#define VTSS_DEVCPU_GCB_GPIO_GPIO_OUT_CLR(ri)  VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0xd + (ri))
#define  VTSS_F_DEVCPU_GCB_GPIO_GPIO_OUT_CLR_G_OUT_CLR(x)  VTSS_ENCODE_BITFIELD(x,0,6)
#define  VTSS_M_DEVCPU_GCB_GPIO_GPIO_OUT_CLR_G_OUT_CLR     VTSS_ENCODE_BITMASK(0,6)
#define  VTSS_X_DEVCPU_GCB_GPIO_GPIO_OUT_CLR_G_OUT_CLR(x)  VTSS_EXTRACT_BITFIELD(x,0,6)

#define VTSS_DEVCPU_GCB_GPIO_GPIO_OUT(ri)    VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0x17 + (ri))
#define  VTSS_F_DEVCPU_GCB_GPIO_GPIO_OUT_G_OUT(x)  VTSS_ENCODE_BITFIELD(x,0,6)
#define  VTSS_M_DEVCPU_GCB_GPIO_GPIO_OUT_G_OUT     VTSS_ENCODE_BITMASK(0,6)
#define  VTSS_X_DEVCPU_GCB_GPIO_GPIO_OUT_G_OUT(x)  VTSS_EXTRACT_BITFIELD(x,0,6)

#define VTSS_DEVCPU_GCB_GPIO_GPIO_IN(ri)     VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0x21 + (ri))
#define  VTSS_F_DEVCPU_GCB_GPIO_GPIO_IN_G_IN(x)  VTSS_ENCODE_BITFIELD(x,0,6)
#define  VTSS_M_DEVCPU_GCB_GPIO_GPIO_IN_G_IN     VTSS_ENCODE_BITMASK(0,6)
#define  VTSS_X_DEVCPU_GCB_GPIO_GPIO_IN_G_IN(x)  VTSS_EXTRACT_BITFIELD(x,0,6)

#define VTSS_DEVCPU_GCB_MIIM_MII_STATUS(gi)  VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,0)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_BUSY  VTSS_BIT(3)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_OPR_PEND  VTSS_BIT(2)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_PENDING_RD  VTSS_BIT(1)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_STAT_PENDING_WR  VTSS_BIT(0)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_STATUS_MIIM_SCAN_COMPLETE  VTSS_BIT(4)

#define VTSS_DEVCPU_GCB_MIIM_MII_CMD(gi)     VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,2)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_VLD  VTSS_BIT(31)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_PHYAD(x)  VTSS_ENCODE_BITFIELD(x,25,5)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_PHYAD     VTSS_ENCODE_BITMASK(25,5)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_PHYAD(x)  VTSS_EXTRACT_BITFIELD(x,25,5)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_REGAD(x)  VTSS_ENCODE_BITFIELD(x,20,5)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_REGAD     VTSS_ENCODE_BITMASK(20,5)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_REGAD(x)  VTSS_EXTRACT_BITFIELD(x,20,5)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_WRDATA(x)  VTSS_ENCODE_BITFIELD(x,4,16)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_WRDATA     VTSS_ENCODE_BITMASK(4,16)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_WRDATA(x)  VTSS_EXTRACT_BITFIELD(x,4,16)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_SINGLE_SCAN  VTSS_BIT(3)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_OPR_FIELD(x)  VTSS_ENCODE_BITFIELD(x,1,2)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_OPR_FIELD     VTSS_ENCODE_BITMASK(1,2)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_OPR_FIELD(x)  VTSS_EXTRACT_BITFIELD(x,1,2)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CMD_MIIM_CMD_SCAN  VTSS_BIT(0)

#define VTSS_DEVCPU_GCB_MIIM_MII_DATA(gi)    VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,3)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_SUCCESS(x)  VTSS_ENCODE_BITFIELD(x,16,2)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_SUCCESS     VTSS_ENCODE_BITMASK(16,2)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_SUCCESS(x)  VTSS_EXTRACT_BITFIELD(x,16,2)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_RDDATA(x)  VTSS_ENCODE_BITFIELD(x,0,16)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_RDDATA     VTSS_ENCODE_BITMASK(0,16)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_DATA_MIIM_DATA_RDDATA(x)  VTSS_EXTRACT_BITFIELD(x,0,16)

#define VTSS_DEVCPU_GCB_MIIM_MII_CFG(gi)     VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,4)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CFG_MIIM_CFG_PRESCALE(x)  VTSS_ENCODE_BITFIELD(x,0,8)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_CFG_MIIM_CFG_PRESCALE     VTSS_ENCODE_BITMASK(0,8)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_CFG_MIIM_CFG_PRESCALE(x)  VTSS_EXTRACT_BITFIELD(x,0,8)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_CFG_MIIM_ST_CFG_FIELD(x)  VTSS_ENCODE_BITFIELD(x,9,2)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_CFG_MIIM_ST_CFG_FIELD     VTSS_ENCODE_BITMASK(9,2)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_CFG_MIIM_ST_CFG_FIELD(x)  VTSS_EXTRACT_BITFIELD(x,9,2)

#define VTSS_DEVCPU_GCB_MIIM_MII_SCAN_0(gi)  VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,5)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_SCAN_0_MIIM_SCAN_PHYADHI(x)  VTSS_ENCODE_BITFIELD(x,5,5)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_SCAN_0_MIIM_SCAN_PHYADHI     VTSS_ENCODE_BITMASK(5,5)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_SCAN_0_MIIM_SCAN_PHYADHI(x)  VTSS_EXTRACT_BITFIELD(x,5,5)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_SCAN_0_MIIM_SCAN_PHYADLO(x)  VTSS_ENCODE_BITFIELD(x,0,5)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_SCAN_0_MIIM_SCAN_PHYADLO     VTSS_ENCODE_BITMASK(0,5)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_SCAN_0_MIIM_SCAN_PHYADLO(x)  VTSS_EXTRACT_BITFIELD(x,0,5)

#define VTSS_DEVCPU_GCB_MIIM_MII_SCAN_1(gi)  VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,6)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_SCAN_1_MIIM_SCAN_MASK(x)  VTSS_ENCODE_BITFIELD(x,16,16)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_SCAN_1_MIIM_SCAN_MASK     VTSS_ENCODE_BITMASK(16,16)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_SCAN_1_MIIM_SCAN_MASK(x)  VTSS_EXTRACT_BITFIELD(x,16,16)
#define  VTSS_F_DEVCPU_GCB_MIIM_MII_SCAN_1_MIIM_SCAN_EXPECT(x)  VTSS_ENCODE_BITFIELD(x,0,16)
#define  VTSS_M_DEVCPU_GCB_MIIM_MII_SCAN_1_MIIM_SCAN_EXPECT     VTSS_ENCODE_BITMASK(0,16)
#define  VTSS_X_DEVCPU_GCB_MIIM_MII_SCAN_1_MIIM_SCAN_EXPECT(x)  VTSS_EXTRACT_BITFIELD(x,0,16)

#define VTSS_DEVCPU_GCB_MIIM_MII_SCAN_LAST_RSLTS(gi)  VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,7)

#define VTSS_DEVCPU_GCB_MIIM_MII_SCAN_LAST_RSLTS_VLD(gi)  VTSS_IOREG_IX(VTSS_TO_DEVCPU_GCB,0x2b,gi,9,0,8)

#define VTSS_DEVCPU_GCB_MIIM_READ_SCAN_MII_SCAN_RSLTS_STICKY(ri)  VTSS_IOREG(VTSS_TO_DEVCPU_GCB,0x3d + (ri))


#endif /* _VTSS_SEVILLE_REGS_DEVCPU_GCB_H_ */
