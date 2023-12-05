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

typedef enum {
	LOGGER_ATTRIBUTE_INVALID,
	LOGGER_ATTRIBUTE_DRIVER_VER,
	LOGGER_ATTRIBUTE_FW_VER,
	LOGGER_ATTRIBUTE_RING_ID,
	LOGGER_ATTRIBUTE_RING_NAME,
	LOGGER_ATTRIBUTE_RING_FLAGS,
	LOGGER_ATTRIBUTE_LOG_LEVEL,
	LOGGER_ATTRIBUTE_LOG_TIME_INTVAL,
	LOGGER_ATTRIBUTE_LOG_MIN_DATA_SIZE,
	LOGGER_ATTRIBUTE_FW_DUMP_LEN,
	LOGGER_ATTRIBUTE_FW_DUMP_DATA,
	LOGGER_ATTRIBUTE_FW_ERR_CODE,
	LOGGER_ATTRIBUTE_RING_DATA,
	LOGGER_ATTRIBUTE_RING_STATUS,
	LOGGER_ATTRIBUTE_RING_NUM,
	LOGGER_ATTRIBUTE_DRIVER_DUMP_LEN,
	LOGGER_ATTRIBUTE_DRIVER_DUMP_DATA,
	LOGGER_ATTRIBUTE_PKT_FATE_NUM,
	LOGGER_ATTRIBUTE_PKT_FATE_DATA,
} LOGGER_ATTRIBUTE;

enum nv_andr_wifi_attr {
	NV_ANDR_WIFI_ATTRIBUTE_INVALID,
	NV_ANDR_WIFI_ATTRIBUTE_NUM_FEATURE_SET,
	NV_ANDR_WIFI_ATTRIBUTE_FEATURE_SET,
	NV_ANDR_WIFI_ATTRIBUTE_RANDOM_MAC_OUI,
	NV_ANDR_WIFI_ATTRIBUTE_NODFS_SET,
	NV_ANDR_WIFI_ATTRIBUTE_COUNTRY,
	NV_ANDR_WIFI_ATTRIBUTE_ND_OFFLOAD_VALUE,
	NV_ANDR_WIFI_ATTRIBUTE_TCPACK_SUP_VALUE
};

int wl_cfgvendor_unsupported_feature(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len);

int wl_cfgvendor_get_ver(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len);

int
wl_cfgvendor_set_pno_mac_oui(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len);

int
nv_android_private_cmd(struct brcmf_pub *drvr, struct net_device *ndev,
	char *command, u32 cmd_len, int *bytes_written);
#endif  /* _nv_cap_h_ */
