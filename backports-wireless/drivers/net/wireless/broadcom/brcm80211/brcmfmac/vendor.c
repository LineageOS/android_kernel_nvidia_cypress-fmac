/*
 * Copyright (c) 2014 Broadcom Corporation
 * Copyright (C) 2019-2021 NVIDIA Corporation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/vmalloc.h>
#include <linux/wakelock.h>
#include <net/cfg80211.h>
#include <net/netlink.h>

#include <brcmu_wifi.h>
#include "fwil_types.h"
#include "core.h"
#include "p2p.h"
#include "debug.h"
#include "cfg80211.h"
#include "vendor.h"
#include "fwil.h"
#include "android.h"

#ifdef CPTCFG_BRCMFMAC_NV_PRIV_CMD
#include "nv_android.h"
#endif /* CPTCFG_BRCMFMAC_NV_PRIV_CMD */

enum andr_vendor_subcmd {
	GSCAN_SUBCMD_GET_CAPABILITIES = 0x1000,
	GSCAN_SUBCMD_SET_CONFIG,
	GSCAN_SUBCMD_SET_SCAN_CONFIG,
	GSCAN_SUBCMD_ENABLE_GSCAN,
	GSCAN_SUBCMD_GET_SCAN_RESULTS,
	GSCAN_SUBCMD_SCAN_RESULTS,
	GSCAN_SUBCMD_SET_HOTLIST,
	GSCAN_SUBCMD_SET_SIGNIFICANT_CHANGE_CONFIG,
	GSCAN_SUBCMD_ENABLE_FULL_SCAN_RESULTS,
	GSCAN_SUBCMD_GET_CHANNEL_LIST,
	ANDR_WIFI_SUBCMD_GET_FEATURE_SET,
	ANDR_WIFI_SUBCMD_GET_FEATURE_SET_MATRIX,
	ANDR_WIFI_RANDOM_MAC_OUI,
	ANDR_WIFI_NODFS_CHANNELS,
	ANDR_WIFI_SET_COUNTRY,
#ifdef CPTCFG_BRCMFMAC_NV_PRIV_CMD
	GSCAN_SUBCMD_SET_EPNO_SSID,
	WIFI_SUBCMD_SET_SSID_WHITELIST,
	WIFI_SUBCMD_SET_LAZY_ROAM_PARAMS,
	WIFI_SUBCMD_ENABLE_LAZY_ROAM,
	WIFI_SUBCMD_SET_BSSID_PREF,
	WIFI_SUBCMD_SET_BSSID_BLACKLIST,
	GSCAN_SUBCMD_ANQPO_CONFIG,
	WIFI_SUBCMD_SET_RSSI_MONITOR,
	WIFI_SUBCMD_SET_LATENCY_MODE = 0x101b,
	RTT_SUBCMD_SET_CONFIG = 0x1100,
	RTT_SUBCMD_CANCEL_CONFIG,
	RTT_SUBCMD_GETCAPABILITY,
	LSTATS_SUBCMD_GET_INFO = 0x1200,
	DEBUG_START_LOGGING = 0x1400,
	DEBUG_TRIGGER_MEM_DUMP,
	DEBUG_GET_MEM_DUMP,
	DEBUG_GET_VER,
	DEBUG_GET_RING_STATUS,
	DEBUG_GET_RING_DATA,
	DEBUG_GET_FEATURE,
	DEBUG_RESET_LOGGING,
	DEBUG_GET_WAKE_REASON_STATS = 0x140d,
	DEBUG_SET_HAL_PID = 0x1412,
#endif /* CPTCFG_BRCMFMAC_NV_PRIV_CMD */
	/* define all wifi calling related commands between 0x1600 and 0x16FF */
	ANDR_OFFLOAD_SUBCMD_START_MKEEP_ALIVE = 0x1600,
	ANDR_OFFLOAD_SUBCMD_STOP_MKEEP_ALIVE,
	ANDR_WIFI_SUBCMD_TX_PWR_SCENARIO = 0x1900,
};

enum gscan_attributes {
	GSCAN_ATTRIBUTE_NUM_BUCKETS = 10,
	GSCAN_ATTRIBUTE_BASE_PERIOD,
	GSCAN_ATTRIBUTE_BUCKETS_BAND,
	GSCAN_ATTRIBUTE_BUCKET_ID,
	GSCAN_ATTRIBUTE_BUCKET_PERIOD,
	GSCAN_ATTRIBUTE_BUCKET_NUM_CHANNELS,
	GSCAN_ATTRIBUTE_BUCKET_CHANNELS,
	GSCAN_ATTRIBUTE_NUM_AP_PER_SCAN,
	GSCAN_ATTRIBUTE_REPORT_THRESHOLD,
	GSCAN_ATTRIBUTE_NUM_SCANS_TO_CACHE,
	GSCAN_ATTRIBUTE_BAND = GSCAN_ATTRIBUTE_BUCKETS_BAND,

	GSCAN_ATTRIBUTE_ENABLE_FEATURE = 20,
	GSCAN_ATTRIBUTE_SCAN_RESULTS_COMPLETE,
	GSCAN_ATTRIBUTE_FLUSH_FEATURE,
	GSCAN_ATTRIBUTE_ENABLE_FULL_SCAN_RESULTS,
	GSCAN_ATTRIBUTE_REPORT_EVENTS,
	GSCAN_ATTRIBUTE_NUM_OF_RESULTS = 30,
	GSCAN_ATTRIBUTE_FLUSH_RESULTS,
	GSCAN_ATTRIBUTE_SCAN_RESULTS,
	GSCAN_ATTRIBUTE_SCAN_ID,
	GSCAN_ATTRIBUTE_SCAN_FLAGS,
	GSCAN_ATTRIBUTE_AP_FLAGS,
	GSCAN_ATTRIBUTE_NUM_CHANNELS,
	GSCAN_ATTRIBUTE_CHANNEL_LIST,
	GSCAN_ATTRIBUTE_CH_BUCKET_BITMASK
};

enum andr_wifi_attr {
	ANDR_WIFI_ATTRIBUTE_NUM_FEATURE_SET,
	ANDR_WIFI_ATTRIBUTE_FEATURE_SET,
	ANDR_WIFI_ATTRIBUTE_RANDOM_MAC_OUI,
	ANDR_WIFI_ATTRIBUTE_NODFS_SET,
	ANDR_WIFI_ATTRIBUTE_COUNTRY,
	ANDR_WIFI_ATTRIBUTE_ND_OFFLOAD_VALUE,
	ANDR_WIFI_ATTRIBUTE_TCPACK_SUP_VALUE
};

enum mkeep_alive_attributes {
	MKEEP_ALIVE_ATTRIBUTE_ID,
	MKEEP_ALIVE_ATTRIBUTE_IP_PKT,
	MKEEP_ALIVE_ATTRIBUTE_IP_PKT_LEN,
	MKEEP_ALIVE_ATTRIBUTE_SRC_MAC_ADDR,
	MKEEP_ALIVE_ATTRIBUTE_DST_MAC_ADDR,
	MKEEP_ALIVE_ATTRIBUTE_PERIOD_MSEC,
	MKEEP_ALIVE_ATTRIBUTE_ETHER_TYPE
};

#define GSCAN_BG_BAND_MASK	0x1
#define GSCAN_A_BAND_MASK	0x2
#define GSCAN_DFS_MASK		0x4
#define GSCAN_ABG_BAND_MASK	(GSCAN_A_BAND_MASK | GSCAN_BG_BAND_MASK)
#define GSCAN_BAND_MASK		(GSCAN_ABG_BAND_MASK | GSCAN_DFS_MASK)

/* Basic infrastructure mode */
#define WIFI_FEATURE_INFRA		0x0001
/* Support for 5 GHz Band */
#define WIFI_FEATURE_INFRA_5G		0x0002
/* Support for GAS/ANQP */
#define WIFI_FEATURE_HOTSPOT		0x0004
/* Wifi-Direct */
#define WIFI_FEATURE_P2P		0x0008
/* Soft AP */
#define WIFI_FEATURE_SOFT_AP		0x0010
/* Google-Scan APIs */
#define WIFI_FEATURE_GSCAN		0x0020
/* Neighbor Awareness Networking */
#define WIFI_FEATURE_NAN		0x0040
/* Device-to-device RTT */
#define WIFI_FEATURE_D2D_RTT		0x0080
/* Device-to-AP RTT */
#define WIFI_FEATURE_D2AP_RTT		0x0100
/* Batched Scan (legacy) */
#define WIFI_FEATURE_BATCH_SCAN		0x0200
/* Preferred network offload */
#define WIFI_FEATURE_PNO		0x0400
/* Support for two STAs */
#define WIFI_FEATURE_ADDITIONAL_STA	0x0800
/* Tunnel directed link setup */
#define WIFI_FEATURE_TDLS		0x1000
/* Support for TDLS off channel */
#define WIFI_FEATURE_TDLS_OFFCHANNEL	0x2000
/* Enhanced power reporting */
#define WIFI_FEATURE_EPR		0x4000
/* Support for AP STA Concurrency */
#define WIFI_FEATURE_AP_STA		0x8000
/* Support for Linkstats */
#define WIFI_FEATURE_LINKSTAT		0x10000
/* WiFi PNO enhanced */
#define WIFI_FEATURE_HAL_EPNO		0x40000
/* RSSI Monitor */
#define WIFI_FEATURE_RSSI_MONITOR	0x80000
/* ND offload configure */
#define WIFI_FEATURE_CONFIG_NDO		0x200000
/* Invalid Feature */
#define WIFI_FEATURE_INVALID		0xFFFFFFFF


/*
 * This API is to be used for asynchronous vendor events. This
 * shouldn't be used in response to a vendor command from its
 * do_it handler context (instead wl_cfgvendor_send_cmd_reply should
 * be used).
 */
int brcmf_cfg80211_vndr_send_async_event(struct wiphy *wiphy,
	struct net_device *dev, int event_id, const void  *data, int len)
{
	u16 kflags;
	struct sk_buff *skb;

	kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;
	skb = cfg80211_vendor_event_skb_alloc(dev, wiphy, len, event_id,
					      kflags);
	/* Alloc the SKB for vendor_event */
	if (!skb) {
		brcmf_err("%s: skb alloc failed", __func__);
		return -ENOMEM;
	}

	/* Push the data to the skb */
	nla_put_nohdr(skb, len, data);

	cfg80211_vendor_event(skb, kflags);

	return 0;
}

static int brcmf_cfg80211_vndr_cmds_dcmd_handler(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 const void *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	const struct brcmf_vndr_dcmd_hdr *cmdhdr = data;
	struct sk_buff *reply;
	int ret, payload, ret_len;
	void *dcmd_buf = NULL, *wr_pointer;
	u16 msglen, maxmsglen = PAGE_SIZE - 0x100;

	if (len < sizeof(*cmdhdr)) {
		brcmf_err("vendor command too short: %d\n", len);
		return -EINVAL;
	}

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	ifp = vif->ifp;

	brcmf_dbg(TRACE, "ifidx=%d, cmd=%d\n", ifp->ifidx, cmdhdr->cmd);

	if (cmdhdr->offset > len) {
		brcmf_err("bad buffer offset %d > %d\n", cmdhdr->offset, len);
		return -EINVAL;
	}

	brcmf_android_wake_lock(ifp->drvr);

	len -= cmdhdr->offset;
	ret_len = cmdhdr->len;
	if (ret_len > 0 || len > 0) {
		if (len > BRCMF_DCMD_MAXLEN) {
			brcmf_err("oversize input buffer %d\n", len);
			len = BRCMF_DCMD_MAXLEN;
		}
		if (ret_len > BRCMF_DCMD_MAXLEN) {
			brcmf_err("oversize return buffer %d\n", ret_len);
			ret_len = BRCMF_DCMD_MAXLEN;
		}
		payload = max(ret_len, len) + 1;
		dcmd_buf = vzalloc(payload);
		if (!dcmd_buf) {
			brcmf_android_wake_unlock(ifp->drvr);
			return -ENOMEM;
		}

		memcpy(dcmd_buf, (void *)cmdhdr + cmdhdr->offset, len);
		*(char *)(dcmd_buf + len)  = '\0';
	}

	if (cmdhdr->set)
		ret = brcmf_fil_cmd_data_set(ifp, cmdhdr->cmd, dcmd_buf,
					     ret_len);
	else
		ret = brcmf_fil_cmd_data_get(ifp, cmdhdr->cmd, dcmd_buf,
					     ret_len);

	if (ret != 0) {
		brcmf_dbg(INFO, "error(%d), return -EPERM\n", ret);
		ret = -EPERM;
		goto exit;
	}

	wr_pointer = dcmd_buf;
	while (ret_len > 0) {
		msglen = ret_len > maxmsglen ? maxmsglen : ret_len;
		ret_len -= msglen;
		payload = msglen + sizeof(msglen);
		reply = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, payload);
		if (NULL == reply) {
			ret = -ENOMEM;
			break;
		}

		if (nla_put(reply, BRCMF_NLATTR_DATA, msglen, wr_pointer) ||
		    nla_put_u16(reply, BRCMF_NLATTR_LEN, msglen)) {
			kfree_skb(reply);
			ret = -ENOBUFS;
			break;
		}

		ret = cfg80211_vendor_cmd_reply(reply);
		if (ret)
			break;

		wr_pointer += msglen;
	}

exit:
	vfree(dcmd_buf);
	brcmf_android_wake_unlock(ifp->drvr);
	return ret;
}

static int
brcmf_cfg80211_gscan_get_channel_list_handler(struct wiphy *wiphy,
					      struct wireless_dev *wdev,
					      const void *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	struct sk_buff *reply;
	int ret, gscan_band, i;
	struct ieee80211_supported_band *band_2g, *band_5g;
	uint *channels;
	uint num_channels = 0;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	ifp = vif->ifp;

	brcmf_android_wake_lock(ifp->drvr);

	brcmf_dbg(TRACE, "ifidx=%d, enter\n", ifp->ifidx);

	if (nla_type(data) == GSCAN_ATTRIBUTE_BAND) {
		gscan_band = nla_get_u32(data);
		if ((gscan_band & GSCAN_BAND_MASK) == 0) {
			ret = -EINVAL;
			goto exit;
		}
	} else {
		ret =  -EINVAL;
		goto exit;
	}

	band_2g = wiphy->bands[NL80211_BAND_2GHZ];
	band_5g = wiphy->bands[NL80211_BAND_5GHZ];
	channels = vzalloc((band_2g->n_channels + band_5g->n_channels) *
			   sizeof(uint));
	if (!channels) {
		ret = -ENOMEM;
		goto exit;
	}

	if (gscan_band & GSCAN_BG_BAND_MASK) {
		for (i = 0; i < band_2g->n_channels; i++) {
			if (band_2g->channels[i].flags &
			    IEEE80211_CHAN_DISABLED)
				continue;
			if (!(gscan_band & GSCAN_DFS_MASK) &&
			    (band_2g->channels[i].flags &
			     (IEEE80211_CHAN_RADAR | IEEE80211_CHAN_NO_IR)))
				continue;

			channels[num_channels] =
			    band_2g->channels[i].center_freq;
			num_channels++;
		}
	}
	if (gscan_band & GSCAN_A_BAND_MASK) {
		for (i = 0; i < band_5g->n_channels; i++) {
			if (band_5g->channels[i].flags &
			    IEEE80211_CHAN_DISABLED)
				continue;
			if (!(gscan_band & GSCAN_DFS_MASK) &&
			    (band_5g->channels[i].flags &
			     (IEEE80211_CHAN_RADAR | IEEE80211_CHAN_NO_IR)))
				continue;

			channels[num_channels] =
			    band_5g->channels[i].center_freq;
			num_channels++;
		}
	}

	reply =
	    cfg80211_vendor_cmd_alloc_reply_skb(wiphy, ((num_channels + 1) *
							sizeof(uint)));
	nla_put_u32(reply, GSCAN_ATTRIBUTE_NUM_CHANNELS, num_channels);
	nla_put(reply, GSCAN_ATTRIBUTE_CHANNEL_LIST,
		num_channels * sizeof(uint), channels);
	ret = cfg80211_vendor_cmd_reply(reply);

	vfree(channels);
exit:
	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static int
brcmf_cfg80211_andr_get_feature_set_handler(struct wiphy *wiphy,
					    struct wireless_dev *wdev,
					    const void *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	struct sk_buff *reply;
	int ret;
	int feature_set = 0;
	char caps[256];

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	ifp = vif->ifp;

	brcmf_android_wake_lock(ifp->drvr);

	brcmf_dbg(TRACE, "ifidx=%d, enter\n", ifp->ifidx);

	ret = brcmf_fil_iovar_data_get(ifp, "cap", caps, sizeof(caps));
	if (ret) {
		brcmf_err("get capa error, ret = %d\n", ret);
		goto exit;
	}

	if (strnstr(caps, "sta", sizeof(caps)))
		feature_set |= WIFI_FEATURE_INFRA;
	if (strnstr(caps, "dualband", sizeof(caps)))
		feature_set |= WIFI_FEATURE_INFRA_5G;
	if (strnstr(caps, "p2p", sizeof(caps)))
		feature_set |= WIFI_FEATURE_P2P;
	if (wdev->iftype == NL80211_IFTYPE_AP ||
	    wdev->iftype == NL80211_IFTYPE_P2P_GO)
		feature_set |= WIFI_FEATURE_SOFT_AP;
	if (strnstr(caps, "tdls", sizeof(caps)))
		feature_set |= WIFI_FEATURE_TDLS;
	if (strnstr(caps, "vsdb", sizeof(caps)))
		feature_set |= WIFI_FEATURE_TDLS_OFFCHANNEL;
	if (strnstr(caps, "nan", sizeof(caps))) {
		feature_set |= WIFI_FEATURE_NAN;
		if (strnstr(caps, "rttd2d", sizeof(caps)))
			feature_set |= WIFI_FEATURE_D2D_RTT;
	}
	/* TODO:
	 * RTT_SUPPORT
	 * LINKSTAT_SUPPORT
	 * PNO_SUPPORT
	 * GSCAN_SUPPORT
	 * RSSI_MONITOR_SUPPORT
	 * WL11U
	 * NDO_CONFIG_SUPPORT
	 */
	reply = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(int));
	nla_put_nohdr(reply, sizeof(int), &feature_set);
	ret = cfg80211_vendor_cmd_reply(reply);
exit:
	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static int
brcmf_cfg80211_andr_set_country_handler(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	struct net_device *ndev;
	int ret;
	char *country_code;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	ifp = vif->ifp;
	ndev = ifp->ndev;

	brcmf_android_wake_lock(ifp->drvr);

	brcmf_dbg(TRACE, "ifidx=%d, enter\n", ifp->ifidx);

	if (nla_type(data) == ANDR_WIFI_ATTRIBUTE_COUNTRY) {
		country_code = nla_data(data);
		brcmf_err("country=%s\n", country_code);
		if (strlen(country_code) != 2)
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	ret = brcmf_set_country(ndev, country_code);
	if (ret)
		brcmf_err("set country code %s failed, ret=%d\n",
			  country_code, ret);

	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static int brcmf_cfg80211_start_mkeep_alive(struct wiphy *wiphy, struct wireless_dev *wdev,
	const void *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	struct net_device *ndev;
	int ret = 0, rem, type;
	u8 mkeep_alive_id = 0;
	u8 *ip_pkt = NULL;
	u16 ip_pkt_len = 0;
	u8 src_mac[ETH_ALEN];
	u8 dst_mac[ETH_ALEN];
	u32 period_msec = 0;
	u16 ether_type = 0;
	const struct nlattr *iter;
	gfp_t kflags = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	ifp = vif->ifp;
	ndev = ifp->ndev;
	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {
			case MKEEP_ALIVE_ATTRIBUTE_ID:
				mkeep_alive_id = nla_get_u8(iter);
				break;
			case MKEEP_ALIVE_ATTRIBUTE_IP_PKT_LEN:
				ip_pkt_len = nla_get_u16(iter);
				if (ip_pkt_len > MKEEP_ALIVE_IP_PKT_MAX) {
					ret = -EOVERFLOW;
					goto exit;
				}
				break;
			case MKEEP_ALIVE_ATTRIBUTE_IP_PKT:
				if (!ip_pkt_len) {
					ret = -EOVERFLOW;
					brcmf_err("ip packet length is 0\n");
					goto exit;
				}
				ip_pkt = (u8 *)kzalloc(ip_pkt_len, kflags);
				if (ip_pkt == NULL) {
					ret = -ENOMEM;
					brcmf_err("Failed to allocate mem for ip packet\n");
					goto exit;
				}
				memcpy(ip_pkt, (u8*)nla_data(iter), ip_pkt_len);
				break;
			case MKEEP_ALIVE_ATTRIBUTE_SRC_MAC_ADDR:
				memcpy(src_mac, nla_data(iter), ETH_ALEN);
				break;
			case MKEEP_ALIVE_ATTRIBUTE_DST_MAC_ADDR:
				memcpy(dst_mac, nla_data(iter), ETH_ALEN);
				break;
			case MKEEP_ALIVE_ATTRIBUTE_PERIOD_MSEC:
				period_msec = nla_get_u32(iter);
				break;
			case MKEEP_ALIVE_ATTRIBUTE_ETHER_TYPE:
				ether_type = nla_get_u16(iter);
				break;
			default:
				brcmf_err("Unknown type: %d\n", type);
				ret = -EINVAL;
				goto exit;
		}
	}

	if (ip_pkt == NULL) {
		ret = -EINVAL;
		brcmf_err("ip packet is NULL\n");
		goto exit;
	}

	ret = brcmf_start_mkeep_alive(ndev, mkeep_alive_id, ip_pkt, ip_pkt_len, src_mac,
		dst_mac, period_msec, ether_type);
	if (ret < 0) {
		brcmf_err("start_mkeep_alive is failed ret: %d\n", ret);
	}

exit:
	kfree(ip_pkt);
	return ret;
}

static int brcmf_cfg80211_stop_mkeep_alive(struct wiphy *wiphy, struct wireless_dev *wdev,
	const void *data, int len)
{
	struct brcmf_cfg80211_vif *vif;
	struct brcmf_if *ifp;
	struct net_device *ndev;
	int ret = 0, rem, type;
	u8 mkeep_alive_id = 0;
	const struct nlattr *iter;

	vif = container_of(wdev, struct brcmf_cfg80211_vif, wdev);
	ifp = vif->ifp;
	ndev = ifp->ndev;

	nla_for_each_attr(iter, data, len, rem) {
		type = nla_type(iter);
		switch (type) {
			case MKEEP_ALIVE_ATTRIBUTE_ID:
				mkeep_alive_id = nla_get_u8(iter);
				break;
			default:
				brcmf_err("Unknown type: %d\n", type);
				ret = -EINVAL;
				break;
		}
	}

	ret = brcmf_stop_mkeep_alive(ndev, mkeep_alive_id);
	if (ret < 0) {
		brcmf_err("stop_mkeep_alive is failed ret: %d\n", ret);
	}

	return ret;
}


const struct wiphy_vendor_command brcmf_vendor_cmds[] = {
	{
		{
			.vendor_id = BROADCOM_OUI,
			.subcmd = BRCMF_VNDR_CMDS_DCMD
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = brcmf_cfg80211_vndr_cmds_dcmd_handler
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = GSCAN_SUBCMD_GET_CHANNEL_LIST
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = brcmf_cfg80211_gscan_get_channel_list_handler
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = ANDR_WIFI_SET_COUNTRY
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = brcmf_cfg80211_andr_set_country_handler
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = ANDR_WIFI_SUBCMD_GET_FEATURE_SET
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = brcmf_cfg80211_andr_get_feature_set_handler
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = ANDR_OFFLOAD_SUBCMD_START_MKEEP_ALIVE
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = brcmf_cfg80211_start_mkeep_alive
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = ANDR_OFFLOAD_SUBCMD_STOP_MKEEP_ALIVE
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = brcmf_cfg80211_stop_mkeep_alive
	},
#ifdef CPTCFG_BRCMFMAC_NV_PRIV_CMD
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = ANDR_WIFI_RANDOM_MAC_OUI
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_set_pno_mac_oui
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_GET_VER
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_get_ver
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_START_LOGGING
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_TRIGGER_MEM_DUMP
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_GET_MEM_DUMP
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_GET_RING_STATUS
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_GET_RING_DATA
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_GET_FEATURE
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_RESET_LOGGING
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = ANDR_WIFI_SUBCMD_TX_PWR_SCENARIO
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = WIFI_SUBCMD_SET_LATENCY_MODE
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_SET_HAL_PID
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
	{
		{
			.vendor_id = GOOGLE_OUI,
			.subcmd = DEBUG_GET_WAKE_REASON_STATS
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = wl_cfgvendor_unsupported_feature
	},
#endif /* CPTCFG_BRCMFMAC_NV_PRIV_CMD */
};

const struct  nl80211_vendor_cmd_info brcmf_vendor_events[] = {
		{ BROADCOM_OUI, BRCM_VENDOR_EVENT_UNSPEC },
		{ BROADCOM_OUI, BRCM_VENDOR_EVENT_PRIV_STR },
		{ GOOGLE_OUI, GOOGLE_GSCAN_SIGNIFICANT_EVENT },
		{ GOOGLE_OUI, GOOGLE_GSCAN_GEOFENCE_FOUND_EVENT },
		{ GOOGLE_OUI, GOOGLE_GSCAN_BATCH_SCAN_EVENT },
		{ GOOGLE_OUI, GOOGLE_SCAN_FULL_RESULTS_EVENT },
		{ GOOGLE_OUI, GOOGLE_RTT_COMPLETE_EVENT },
		{ GOOGLE_OUI, GOOGLE_SCAN_COMPLETE_EVENT },
		{ GOOGLE_OUI, GOOGLE_GSCAN_GEOFENCE_LOST_EVENT },
		{ GOOGLE_OUI, GOOGLE_SCAN_EPNO_EVENT },
		{ GOOGLE_OUI, GOOGLE_DEBUG_RING_EVENT },
		{ GOOGLE_OUI, GOOGLE_FW_DUMP_EVENT },
		{ GOOGLE_OUI, GOOGLE_PNO_HOTSPOT_FOUND_EVENT },
		{ GOOGLE_OUI, GOOGLE_RSSI_MONITOR_EVENT },
		{ GOOGLE_OUI, GOOGLE_MKEEP_ALIVE_EVENT },
		{ BROADCOM_OUI, BRCM_VENDOR_EVENT_IDSUP_STATUS },
		{ BROADCOM_OUI, BRCM_VENDOR_EVENT_DRIVER_HANG }
};

void brcmf_set_vndr_cmd(struct wiphy *wiphy)
{
	wiphy->vendor_commands = brcmf_vendor_cmds;
	wiphy->n_vendor_commands = ARRAY_SIZE(brcmf_vendor_cmds);
	wiphy->vendor_events	= brcmf_vendor_events;
	wiphy->n_vendor_events	= ARRAY_SIZE(brcmf_vendor_events);
}
