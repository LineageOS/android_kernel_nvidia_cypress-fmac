/*
 * nv_debug.h
 *
 * NVIDIA Tegra debug messages for brcmfmac driver
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

#ifndef _nv_debug_h_
#define _nv_debug_h_
#include <linux/time.h>

#define NV_TIMESTAMP() \
	do { \
		struct timeval now; \
		struct tm date_time; \
		do_gettimeofday(&now); \
		time_to_tm(now.tv_sec, -sys_tz.tz_minuteswest * 60, &date_time); \
		pr_info("[%.2d-%.2d %.2d:%.2d:%.2d.%u]: ",	\
			date_time.tm_mon+1, date_time.tm_mday, date_time.tm_hour, \
			date_time.tm_min, date_time.tm_sec, \
			(unsigned int)(now.tv_usec/1000)); \
	} while (0)

#define NV_DEBUG_PRINT(args) \
	do { \
		NV_TIMESTAMP(); \
		pr_cont args; \
	} while (0)

void nv_debug_skb(struct sk_buff *skb, char *netif, bool direction);
void nv_debug_cmd(struct brcmf_if *ifp, u32 cmd, void *data, u32 len,
			bool set, s32 err);
void nv_debug_fwevents(struct brcmf_if *ifp,
			struct brcmf_event_msg *emsg,
			void *data);
#endif  /* _nv_debug_h_ */
