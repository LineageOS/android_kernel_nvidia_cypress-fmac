/*
 * Copyright (c) 2014 Broadcom Corporation
 * Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
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

#ifndef _vendor_h_
#define _vendor_h_

#define BROADCOM_OUI	0x001018
#define GOOGLE_OUI	0x001A11

enum brcmf_vndr_cmds {
	BRCMF_VNDR_CMDS_UNSPEC,
	BRCMF_VNDR_CMDS_DCMD,
	BRCMF_VNDR_CMDS_LAST
};

/**
 * enum brcmf_nlattrs - nl80211 message attributes
 *
 * @BRCMF_NLATTR_LEN: message body length
 * @BRCMF_NLATTR_DATA: message body
 */
enum brcmf_nlattrs {
	BRCMF_NLATTR_UNSPEC,

	BRCMF_NLATTR_LEN,
	BRCMF_NLATTR_DATA,

	__BRCMF_NLATTR_AFTER_LAST,
	BRCMF_NLATTR_MAX = __BRCMF_NLATTR_AFTER_LAST - 1
};

/**
 * struct brcmf_vndr_dcmd_hdr - message header for cfg80211 vendor command dcmd
 *				support
 *
 * @cmd: common dongle cmd definition
 * @len: length of expecting return buffer
 * @offset: offset of data buffer
 * @set: get or set request(optional)
 * @magic: magic number for verification
 */
struct brcmf_vndr_dcmd_hdr {
	uint cmd;
	int len;
	uint offset;
	uint set;
	uint magic;
};

enum brcmf_vendor_event {
	BRCM_VENDOR_EVENT_UNSPEC,
	BRCM_VENDOR_EVENT_PRIV_STR,
	GOOGLE_GSCAN_SIGNIFICANT_EVENT,
	GOOGLE_GSCAN_GEOFENCE_FOUND_EVENT,
	GOOGLE_GSCAN_BATCH_SCAN_EVENT,
	GOOGLE_SCAN_FULL_RESULTS_EVENT,
	GOOGLE_RTT_COMPLETE_EVENT,
	GOOGLE_SCAN_COMPLETE_EVENT,
	GOOGLE_GSCAN_GEOFENCE_LOST_EVENT,
	GOOGLE_SCAN_EPNO_EVENT,
	GOOGLE_DEBUG_RING_EVENT,
	GOOGLE_FW_DUMP_EVENT,
	GOOGLE_PNO_HOTSPOT_FOUND_EVENT,
	GOOGLE_RSSI_MONITOR_EVENT,
	GOOGLE_MKEEP_ALIVE_EVENT,
	BRCM_VENDOR_EVENT_IDSUP_STATUS,
	BRCM_VENDOR_EVENT_DRIVER_HANG,
	BRCMF_VNDR_EVENT_LAST
};

extern const struct wiphy_vendor_command brcmf_vendor_cmds[];
extern const struct nl80211_vendor_cmd_info brcmf_vendor_events[];

void brcmf_set_vndr_cmd(struct wiphy *wiphy);
int brcmf_cfg80211_vndr_send_async_event(struct wiphy *wiphy,
	struct net_device *dev, int event_id, const void  *data, int len);

#endif /* _vendor_h_ */
