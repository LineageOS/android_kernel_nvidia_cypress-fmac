/*
 * nv_android.h
 *
 * NVIDIA Tegra NvCap for brcmfmac driver
 *
 * Copyright (C) 2019 NVIDIA Corporation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef _nv_android_h_
#define _nv_android_h_


int
nv_android_private_cmd(struct brcmf_pub *drvr, struct net_device *ndev,
	char *command, u32 cmd_len, int *bytes_written);
#endif  /* _nv_cap_h_ */
