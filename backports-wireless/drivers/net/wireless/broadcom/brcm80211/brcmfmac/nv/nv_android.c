/*
 * nv_android.c
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
#include <linux/mmc/card.h>
#include <linux/wakelock.h>
#include <defs.h>
#include <brcmu_utils.h>
#include <brcmu_wifi.h>
#include "core.h"
#include "android.h"
#include "cfg80211.h"
#include "debug.h"
#include "fwil.h"
#include "nv_common.h"
#include "nv_android.h"
#include "pno.h"
#include "vendor.h"

#define CMD_RSSI		"RSSI"
#define CMD_LINKSPEED		"LINKSPEED"

#define CMD_SET_IM_MODE		"SETMIRACAST"
#define CMD_UPDATE_CHANNEL_LIST	"UPDATE_CHANNEL_LIST"
#define CMD_RESTRICT_BW_20	"RESTRICT_BW_20"
#define CMD_MAXLINKSPEED	"MAXLINKSPEED"
#define CMD_SETROAMMODE		"SETROAMMODE"
#define CMD_AUTOSLEEP		"AUTOSLEEP" /* only for SDIO based chip */
#define CMD_SET_WPS_P2PIE	"SET_AP_WPS_P2P_IE"
#define CMD_SETBTCPARAMS	"SETBTCPARAMS"
#define CMD_GETBTCPARAMS	"GETBTCPARAMS"
#define CMD_MKEEP_ALIVE		"MKEEP_ALIVE" /* TODO */
#define CMD_SETBAND		"SETBAND"
#define CMD_TEST_HANGEVENT	"TEST_HANGEVENT"

u32 restrict_bw_20;
bool builtin_roam_disabled;

static int wl_android_get_link_speed(struct brcmf_if *ifp, char *command, int total_len)
{
	int link_speed;
	int bytes_written;
	int err;

	err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_RATE, &link_speed);
	if (err < 0) {
		brcmf_err("BRCMF_C_GET_RATE error (%d)\n", err);
		return err;
	}

	/* Convert Kbps to Android Mbps */
	link_speed = link_speed / 1000;
	bytes_written = snprintf(command, total_len, "LinkSpeed %d", link_speed);
	brcmf_dbg(INFO, "%s: command result is %s\n", __func__, command);
	return bytes_written;
}

static int wl_android_get_rssi(struct brcmf_if *ifp, char *command, int total_len)
{
	struct brcmf_scb_val_le scbval;
	int bytes_written;
	int rssi;
	int err;

	memset(&scbval, 0, sizeof(scbval));
	err = brcmf_fil_cmd_data_get(ifp, BRCMF_C_GET_RSSI, &scbval,
				     sizeof(scbval));
	if (err) {
		brcmf_err("BRCMF_C_GET_RSSI error (%d)\n", err);
		return err;
	}
	rssi = le32_to_cpu(scbval.val);

	bytes_written = snprintf(command, total_len, "rssi %d", rssi);
	brcmf_dbg(INFO, "%s: command result is %s\n", __func__, command);
	return bytes_written;
}

static int wl_android_setband(struct net_device *ndev, struct wiphy *wiphy,
			       struct brcmf_if *ifp, char *command)
{
	int err = -1;
	uint band = *(command + strlen(CMD_SETBAND) + 1) - '0';
	uint curr_band = 0;

	brcmf_info("wl_android_setband: %d ", band);
	if ((band == WLC_BAND_AUTO) || (band == WLC_BAND_5G) ||
		(band == WLC_BAND_2G)) {
		err = brcmf_fil_cmd_int_get(ifp, BRCMF_C_GET_BAND, &curr_band);
		if (err) {
			brcmf_err("%s: getband failed err: %d", __func__, err);
			return err;
		}
		err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_BAND, band);
		if (!err) {
			err = brcmf_setup_wiphybands(wiphy);
			if (!err)
				wiphy_apply_custom_regulatory(wiphy, &brcmf_regdom);
			else
				brcmf_err("%s: setup wiphybands failed err: %d", __func__, err);
		} else {
			brcmf_err("%s: setband failed err: %d", __func__, err);
			/* restore old band setting */
			brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_BAND, curr_band);
			return err;
		}
	} else {
		err = -EINVAL;
	}

	return err;
}

int
nv_android_private_cmd(struct brcmf_pub *drvr, struct net_device *ndev,
	char *command, u32 cmd_len, int *bytes_written)
{
	int ret = 1;
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	struct wiphy *wiphy = NULL;
	int skip = 0;
	int val;
	u32 driver_status = 0;

	if (!bytes_written)
		return -EINVAL;
	if (!wdev)
		return -ENODEV;
	wiphy = wdev->wiphy;
	brcmf_err("command = %s received\n", command);

	if (strncmp(command, CMD_SET_IM_MODE,
			strlen(CMD_SET_IM_MODE)) == 0) {
		*bytes_written =
			nv_brcmf_android_set_im_mode(drvr, ndev, command,
						cmd_len);
	} else if (strncmp(command, CMD_SET_WPS_P2PIE,
		   strlen(CMD_SET_WPS_P2PIE)) == 0) {
		skip = strlen(CMD_SET_WPS_P2PIE) + 3;
		*bytes_written =
			brcmf_cfg80211_set_ap_wps_p2p_ie(ifp->vif, command + skip,
						(cmd_len - skip), *(command + skip - 2) - '0');
	} else if (strncmp(command, CMD_UPDATE_CHANNEL_LIST,
			strlen(CMD_UPDATE_CHANNEL_LIST)) == 0) {
		brcmf_setup_wiphybands(wiphy);
	} else if (strncmp(command, CMD_RESTRICT_BW_20, strlen(CMD_RESTRICT_BW_20)) == 0) {
		*bytes_written = -1;
		val = *(command + strlen(CMD_RESTRICT_BW_20) + 1) - '0';
		if (val == 0 || val == 1) {
			restrict_bw_20 = val;
			*bytes_written = 0;
		}
	} else if (strncmp(command, CMD_MAXLINKSPEED, strlen(CMD_MAXLINKSPEED)) == 0) {
		*bytes_written = brcmf_get_max_linkspeed(ndev, command, cmd_len);
	} else if (!builtin_roam_disabled && strncmp(command, CMD_SETROAMMODE, strlen(CMD_SETROAMMODE)) == 0) {
		 *bytes_written = nv_set_roam_mode(ndev, command, cmd_len);
	} else if (strncmp(command, CMD_SETBTCPARAMS, strlen(CMD_SETBTCPARAMS)) == 0) {
		*bytes_written = nv_btcoex_set_btcparams(ndev, command, cmd_len);
	} else if (strncmp(command, CMD_GETBTCPARAMS, strlen(CMD_GETBTCPARAMS)) == 0) {
		*bytes_written = nv_btcoex_get_btcparams(ndev, command, cmd_len);
	} else if (strncmp(command, CMD_MKEEP_ALIVE,
		strlen(CMD_MKEEP_ALIVE)) == 0) {
		brcmf_err("CMD_MKEEP_ALIVE not supported\n");
	} else if (strncmp(command, CMD_LINKSPEED, strlen(CMD_LINKSPEED)) == 0) {
		*bytes_written = wl_android_get_link_speed(ifp, command, cmd_len);
	} else if (strncmp(command, CMD_RSSI, strlen(CMD_RSSI)) == 0) {
		*bytes_written = wl_android_get_rssi(ifp, command, cmd_len);
	} else if (strncmp(command, CMD_SETBAND, strlen(CMD_SETBAND)) == 0) {
		struct brcmf_cfg80211_info *cfg;

		cfg = wiphy_priv(wiphy);
		brcmf_abort_scanning(cfg);
		*bytes_written = wl_android_setband(ndev, wiphy, ifp, command);
	} else if (strncmp(command, CMD_TEST_HANGEVENT,
		   strlen(CMD_TEST_HANGEVENT)) == 0) {
		*bytes_written = brcmf_cfg80211_vndr_send_async_event(wiphy,
			ndev, BRCM_VENDOR_EVENT_DRIVER_HANG, &driver_status,
			sizeof(u32));
	} else {
		return -EINVAL;
	}

	return ret;
}

int wl_cfgvendor_unsupported_feature(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	// return unsupported error code
	return WIFI_ERROR_NOT_SUPPORTED;
}

int wl_cfgvendor_get_ver(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	struct brcmf_pub *drvr;
	struct sk_buff *reply;
	u8 buf[BRCMF_DCMD_SMLEN] = "n/a";
	int type, ret;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	if (!vif)
		return -EINVAL;

	ifp = vif->ifp;
	if (!ifp)
		return -EINVAL;

	drvr = ifp->drvr;
	if (!drvr)
		return -EINVAL;

	brcmf_android_wake_lock(ifp->drvr);
	ret = WIFI_SUCCESS;
	type = nla_type(data);
	if (type == LOGGER_ATTRIBUTE_DRIVER_VER) {
		/* get driver version */
		if (drvr->revinfo.result == 0) {
			memset(buf, 0, sizeof(buf));
			brcmu_dotrev_str(drvr->revinfo.driverrev, buf);
		}
		brcmf_dbg(INFO, "Driver version = %s\n", buf);
	} else if (type == LOGGER_ATTRIBUTE_FW_VER) {
		/* query for 'ver' to get version info from firmware */
		memset(buf, 0, sizeof(buf));
		strncpy(buf, drvr->fwver, strlen(drvr->fwver));
		brcmf_dbg(INFO, "Firmware version = %s\n", buf);
	} else {
		brcmf_err("Unsupported Loggler %d\n", type);
		ret = WIFI_ERROR_NOT_SUPPORTED;
		goto exit;
	}

	brcmf_dbg(INFO,"Type:%d ret buf:%s\n", type, buf);
	reply = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, strlen(buf));
	nla_put(reply, type, strlen(buf), buf);
	ret = cfg80211_vendor_cmd_reply(reply);

exit:
	brcmf_android_wake_unlock(ifp->drvr);
	return ret;
}

int
wl_cfgvendor_set_pno_mac_oui(struct wiphy *wiphy,
	struct wireless_dev *wdev, const void  *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	struct brcmf_pno_info *pi;
	int type;

	type = nla_type(data);
	if (type != NV_ANDR_WIFI_ATTRIBUTE_RANDOM_MAC_OUI) {
		return -1;
	}

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	if (!vif)
		return -EINVAL;

	ifp = vif->ifp;
	if (!ifp)
		return -EINVAL;

	pi = ifp_to_pno(ifp);
	if (!pi)
		return -EINVAL;
	memcpy(&pi->pno_oui, nla_data(data), PNO_OUI_LEN);

	return 0;
}
