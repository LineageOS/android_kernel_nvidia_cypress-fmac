/*
 * nv_debug.c
 *
 * NVIDIA Tegra debug messages for brcmfmac driver
 *
 * Copyright (C) 2019-2021 NVIDIA Corporation. All rights reserved.
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

#ifdef CPTCFG_NV_DEBUG
#include <linux/types.h>
#include <linux/if_ether.h>

#include <brcmu_d11.h>
#include "cfg80211.h"
#include "core.h"
#include "fwil.h"
#include "debug.h"
#include "nv_debug.h"

#ifdef CPTCFG_NV_CUSTOM_SYSFS_TEGRA
#include "nv_custom_sysfs_tegra.h"
#endif /* CPTCFG_NV_CUSTOM_SYSFS_TEGRA */

#define JOIN_IOVAR "join\0"

static const char * const nv_brcmf_fil_errstr[] = {
	"BCME_OK",
	"BCME_ERROR",
	"BCME_BADARG",
	"BCME_BADOPTION",
	"BCME_NOTUP",
	"BCME_NOTDOWN",
	"BCME_NOTAP",
	"BCME_NOTSTA",
	"BCME_BADKEYIDX",
	"BCME_RADIOOFF",
	"BCME_NOTBANDLOCKED",
	"BCME_NOCLK",
	"BCME_BADRATESET",
	"BCME_BADBAND",
	"BCME_BUFTOOSHORT",
	"BCME_BUFTOOLONG",
	"BCME_BUSY",
	"BCME_NOTASSOCIATED",
	"BCME_BADSSIDLEN",
	"BCME_OUTOFRANGECHAN",
	"BCME_BADCHAN",
	"BCME_BADADDR",
	"BCME_NORESOURCE",
	"BCME_UNSUPPORTED",
	"BCME_BADLEN",
	"BCME_NOTREADY",
	"BCME_EPERM",
	"BCME_NOMEM",
	"BCME_ASSOCIATED",
	"BCME_RANGE",
	"BCME_NOTFOUND",
	"BCME_WME_NOT_ENABLED",
	"BCME_TSPEC_NOTFOUND",
	"BCME_ACM_NOTSUPPORTED",
	"BCME_NOT_WME_ASSOCIATION",
	"BCME_SDIO_ERROR",
	"BCME_DONGLE_DOWN",
	"BCME_VERSION",
	"BCME_TXFAIL",
	"BCME_RXFAIL",
	"BCME_NODEVICE",
	"BCME_NMODE_DISABLED",
	"BCME_NONRESIDENT",
	"BCME_SCANREJECT",
	"BCME_USAGE_ERROR",
	"BCME_IOCTL_ERROR",
	"BCME_SERIAL_PORT_ERR",
	"BCME_DISABLED",
	"BCME_DECERR",
	"BCME_ENCERR",
	"BCME_MICERR",
	"BCME_REPLAY",
	"BCME_IE_NOTFOUND",
};

static const char *nv_brcmf_fil_get_errstr(u32 err)
{
	if (err >= ARRAY_SIZE(nv_brcmf_fil_errstr))
		return "(unknown)";

	return nv_brcmf_fil_errstr[err];
}

static const char *nv_brcmf_fil_eventstr(u32 code)
{
	switch (code) {
	case BRCMF_E_LINK:
		return "BRCMF_E_LINK";
	case BRCMF_E_DEAUTH_IND:
		return "BRCMF_E_DEAUTH_IND";
	case BRCMF_E_DEAUTH:
		return "BRCMF_E_DEAUTH";
	case BRCMF_E_DISASSOC_IND:
		return "BRCMF_E_DISASSOC_IND";
	case BRCMF_E_ASSOC_IND:
		return "BRCMF_E_ASSOC_IND";
	case BRCMF_E_REASSOC_IND:
		return "BRCMF_E_REASSOC_IND";
	case BRCMF_E_SET_SSID:
		return "BRCMF_E_SET_SSID";
	case BRCMF_E_PSK_SUP:
		return "BRCMF_E_PSK_SUP";
	}
	return "";
}

static const char *nv_brcmf_fil_cmdstr(u32 cmd)
{
	switch (cmd) {
	case BRCMF_C_DISASSOC:
		return "BRCMF_C_DISASSOC";
	case BRCMF_C_SET_SSID:
		return "BRCMF_C_SET_SSID";
	case BRCMF_C_GET_SSID:
		return "BRCMF_C_GET_SSID";
	case BRCMF_C_SCAN:
		return "BRCMF_C_SCAN";
	case BRCMF_C_GET_VAR:
		return "BRCMF_C_GET_VAR";
	case BRCMF_C_SET_VAR:
		return "BRCMF_C_SET_VAR";
	}
	return "";
}

static bool nv_debug_is_linkup(struct brcmf_cfg80211_vif *vif,
			    const struct brcmf_event_msg *e)
{
	u32 event = e->event_code;
	u32 status = e->status;

	if ((event == BRCMF_E_PSK_SUP &&
	    status == BRCMF_E_STATUS_FWSUP_COMPLETED) &&
	    (vif->profile.use_fwsup == BRCMF_PROFILE_FWSUP_1X))
		return true;

	if ((event == BRCMF_E_SET_SSID && status == BRCMF_E_STATUS_SUCCESS) &&
	    (vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_PSK &&
	    vif->profile.use_fwsup != BRCMF_PROFILE_FWSUP_SAE))
		return true;

	if (test_bit(BRCMF_VIF_STATUS_EAP_SUCCESS, &vif->sme_state) &&
	    test_bit(BRCMF_VIF_STATUS_ASSOC_SUCCESS, &vif->sme_state))
		return true;

	return false;
}

static bool nv_debug_is_linkdown(const struct brcmf_event_msg *e)
{
	u32 event = e->event_code;
	u16 flags = e->flags;

	if ((event == BRCMF_E_DEAUTH) || (event == BRCMF_E_DEAUTH_IND) ||
	    (event == BRCMF_E_DISASSOC_IND) ||
	    ((event == BRCMF_E_LINK) && (!(flags & BRCMF_EVENT_MSG_LINK)))) {
		return true;
	}
	return false;
}

static void nv_dhcp_messages(char *dump_data, char *netif, bool direction)
{
	u16 dump_hex;
	u16 source_port;
	u16 dest_port;
	u16 udp_port_pos = (dump_data[0] & 0x0f) << 2;

	source_port = (dump_data[udp_port_pos] << 8) |
			dump_data[udp_port_pos + 1];
	dest_port = (dump_data[udp_port_pos + 2] << 8) |
			dump_data[udp_port_pos + 3];

	if (source_port == 0x0044 || dest_port == 0x0044) {
		dump_hex = (dump_data[udp_port_pos+249] << 8) |
			dump_data[udp_port_pos+250];
		if (dump_hex == 0x0101) {
			NV_DEBUG_PRINT(("[%s][%s] DHCP: DISCOVER\n",
					netif, direction ? "TX" : "RX"));
		} else if (dump_hex == 0x0102) {
			NV_DEBUG_PRINT(("[%s][%s] DHCP: OFFER\n",
					netif, direction ? "TX" : "RX"));
		} else if (dump_hex == 0x0103) {
			NV_DEBUG_PRINT(("[%s][%s] DHCP: REQUEST\n",
					netif, direction ? "TX" : "RX"));
		} else if (dump_hex == 0x0105) {
			NV_DEBUG_PRINT(("[%s][%s] DHCP: ACK\n",
					netif, direction ? "TX" : "RX"));
#ifdef CPTCFG_BRCMFMAC_NV_NET_BW_EST_TEGRA
			/* activate bw_estimator since DHCP is completed */
			if (!direction) { // direction should be RX for STA mode
				/* the actual bw can never be one. So using value 1 as flag*/
				bcmdhd_stat.driver_stat.cur_bw_est = 1;
			}
#endif /* CPTCFG_BRCMFMAC_NV_NET_BW_EST_TEGRA */
		} else {
			NV_DEBUG_PRINT(("[%s][%s] DHCP: 0x%X\n",
					netif, direction ? "TX" : "RX",
					dump_hex));
		}
	} else if (source_port == 0x0043 || dest_port == 0x0043) {
		NV_DEBUG_PRINT(("[%s][%s] DHCP: BOOTP\n",
				netif, direction ? "TX" : "RX"));
	}
}

/* Parse EAPOL 4 way handshake messages for debug */
static void nv_eapol_message(char *dump_data, char *netif, bool direction)
{
	u32 pair, ack, mic, kerr, req, sec, install;
	u16 us_tmp;
	u8 type;

	/* Extract EAPOL Key type from 802.1x authentication header
	 * EAPOL WPA2 key type - 2, EAPOL WPA key type - 254
	 */
	type = dump_data[4];
	if (type == 2 || type == 254) {
		us_tmp = (dump_data[5] << 8) | dump_data[6];
		pair = 0 != (us_tmp & 0x08);
		ack = 0 != (us_tmp & 0x80);
		mic = 0 != (us_tmp & 0x100);
		kerr = 0 != (us_tmp & 0x400);
		req = 0 != (us_tmp & 0x800);
		sec = 0 != (us_tmp & 0x200);
		install = 0 != (us_tmp & 0x40);

		if (!sec && !mic && ack && !install && pair && !kerr && !req)
			NV_DEBUG_PRINT(("[%s][%s] EAPOL: M1 of 4way\n",
					netif, direction ? "TX" : "RX"));
		else if (pair && !install && !ack && mic &&
				!sec && !kerr && !req)
			NV_DEBUG_PRINT(("[%s][%s] EAPOL: M2 of 4way\n",
					netif, direction ? "TX" : "RX"));
		else if (pair && ack && mic && sec && !kerr && !req)
			NV_DEBUG_PRINT(("[%s][%s] EAPOL: M3 of 4way\n",
					netif, direction ? "TX" : "RX"));
		else if (pair && !install && !ack && mic &&
				sec && !req && !kerr)
			NV_DEBUG_PRINT(("[%s][%s] EAPOL: M4 of 4way\n",
					netif, direction ? "TX" : "RX"));
	}
}

void nv_debug_skb(struct sk_buff *skb, char *netif, bool direction)
{
	char *dump_data = NULL;
	u16 protocol;

	/* Get protocol and IP data pointer */
	if (direction) {
		dump_data = skb->data;
		protocol = (dump_data[12] << 8) | dump_data[13];
		dump_data = skb->data + ETH_HLEN;
	} else {
		protocol = ntohs(skb->protocol);
		dump_data = skb->data;
	}

	/* check for EAPOL messages */
	if (protocol == ETH_P_PAE)
		nv_eapol_message(dump_data, netif, direction);
	else if (protocol == ETH_P_IP)
		nv_dhcp_messages(dump_data, netif, direction);
}

void nv_debug_cmd(struct brcmf_if *ifp, u32 cmd, void *data, u32 len,
		bool set, s32 err)
{
	struct brcmf_cfg80211_info *cfg = ifp->drvr->config;
	char *netif = NULL;
	struct brcmu_chan ch;
	struct brcmf_ext_join_params_le *ext_join_params = NULL;
	struct brcmf_scb_val_le *scbval = NULL;
	struct brcmf_join_params *join_params = NULL;

	if (ifp->ndev)
		netif = ifp->ndev->name;

	switch (cmd) {
	case BRCMF_C_DISASSOC:
		scbval = (struct brcmf_scb_val_le *)data;
		NV_DEBUG_PRINT(("[%s] %s with reason_code:%d return %s\n",
			(netif != NULL) ? netif : " ",
			nv_brcmf_fil_cmdstr(cmd),
			(scbval != NULL) ? scbval->val : -1,
			nv_brcmf_fil_get_errstr((u32)(-err))));
		break;
	case BRCMF_C_SET_SSID:
		join_params = (struct brcmf_join_params *)data;
		if (!join_params)
			break;

		ch.chspec = join_params->params_le.chanspec_list[0];
		cfg->d11inf.decchspec(&ch);
		NV_DEBUG_PRINT(("[%s] %s SSID:%s BSSID:%pM channel:%d return %s\n",
			(netif != NULL) ? netif : " ",
			nv_brcmf_fil_cmdstr(cmd),
			join_params->ssid_le.SSID,
			join_params->params_le.bssid,
			ch.chnum,
			nv_brcmf_fil_get_errstr((u32)(-err))));
		break;
	case BRCMF_C_SET_VAR:
		if (strncmp(JOIN_IOVAR, data, sizeof(JOIN_IOVAR)) == 0) {
			ext_join_params =
				(struct brcmf_ext_join_params_le *)
				(data + sizeof(JOIN_IOVAR) - 1);
			ch.chspec = ext_join_params->assoc_le.chanspec_list[0];
			cfg->d11inf.decchspec(&ch);
			NV_DEBUG_PRINT(("[%s] IOVAR join SSID:%s BSSID:%pM "
					"channel:%d return %s\n",
				(netif != NULL) ? netif : " ",
				ext_join_params->ssid_le.SSID,
				ext_join_params->assoc_le.bssid,
				ch.chnum,
				nv_brcmf_fil_get_errstr((u32)(-err))));
		}
		break;
	}
}

void nv_debug_fwevents(struct brcmf_if *ifp,
			struct brcmf_event_msg *emsg,
			void *data)
{
	char *netif = NULL;
	u32 event = emsg->event_code;

	if (ifp && ifp->ndev)
		netif = ifp->ndev->name;

	switch (event) {
	case BRCMF_E_LINK:
	case BRCMF_E_DEAUTH_IND:
	case BRCMF_E_DEAUTH:
	case BRCMF_E_DISASSOC_IND:
	case BRCMF_E_ASSOC_IND:
	case BRCMF_E_REASSOC_IND:
	case BRCMF_E_SET_SSID:
		if (nv_debug_is_linkup(ifp->vif, emsg)) {
			NV_DEBUG_PRINT(("[%s] Linkup event:%s status:%d reason:%d\n",
				(netif != NULL) ? netif : " ",
				nv_brcmf_fil_eventstr(event),
				emsg->status,
				emsg->reason));
		} else if (nv_debug_is_linkdown(emsg)) {
			NV_DEBUG_PRINT(("[%s] Linkdown event:%s status:%d reason:%d\n",
				(netif != NULL) ? netif : " ",
				nv_brcmf_fil_eventstr(event),
				emsg->status,
				emsg->reason));
		}
		break;
	}
}
#endif /*CPTCFG_NV_DEBUG */
