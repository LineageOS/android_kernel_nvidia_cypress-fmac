/*
 * Copyright (c) 2010 Broadcom Corporation
 * Copyright (C) 2018-2021 NVIDIA Corporation. All rights reserved.
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

#include <linux/kernel.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/inetdevice.h>
#include <linux/wakelock.h>
#include <net/cfg80211.h>
#include <net/rtnetlink.h>
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <brcmu_utils.h>
#include <brcmu_wifi.h>
#include <linux/regulator/consumer.h>
#include <defs.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "core.h"
#include "bus.h"
#include "debug.h"
#include "fwil_types.h"
#include "p2p.h"
#include "pno.h"
#include "cfg80211.h"
#include "fwil.h"
#include "feature.h"
#include "proto.h"
#include "pcie.h"
#include "common.h"
#include "android.h"
#include "fwsignal.h"

#ifdef CPTCFG_BRCMFMAC_NV_CUSTOM_FILES
#include "nv_common.h"
#endif /* CPTCFG_BRCMFMAC_NV_CUSTOM_FILES */
#ifdef CPTCFG_NV_CUSTOM_SYSFS_TEGRA
#include "nv_custom_sysfs_tegra.h"
#endif /* CPTCFG_NV_CUSTOM_SYSFS_TEGRA */

#define MAX_WAIT_FOR_8021X_TX			msecs_to_jiffies(950)

#define PRIVATE_COMMAND_MAX_LEN			8192

#define BRCMF_BSSIDX_INVALID			-1

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
#define MAX_WAIT_FOR_BUS_START			msecs_to_jiffies(60000)
struct brcmf_pub *g_drvr;
#endif

#ifdef CPTCFG_NV_CUSTOM_SYSFS_TEGRA
extern struct net_device *dhd_custom_sysfs_tegra_histogram_stat_netdev;
#endif /* CPTCFG_NV_CUSTOM_SYSFS_TEGRA */

static int brcmf_android_netdev_open(struct net_device *ndev);
static int brcmf_android_netdev_stop(struct net_device *ndev);
static int brcmf_android_ioctl_entry(struct net_device *net,
				     struct ifreq *ifr, int cmd);
static netdev_tx_t brcmf_android_netdev_start_xmit(struct sk_buff *skb,
						   struct net_device *ndev);
static int brcmf_android_netdev_set_mac_address(struct net_device *ndev,
						void *addr);
static int brcmf_android_net_p2p_open(struct net_device *ndev);
static int brcmf_android_net_p2p_stop(struct net_device *ndev);
static int brcmf_android_priv_cmd(struct net_device *ndev, struct ifreq *ifr,
				  int cmd);
static netdev_tx_t brcmf_android_net_p2p_start_xmit(struct sk_buff *skb,
						    struct net_device *ndev);

char *brcmf_ifname(struct brcmf_if *ifp)
{
	if (!ifp)
		return "<if_null>";

	if (ifp->ndev)
		return ifp->ndev->name;

	return "<if_none>";
}

struct brcmf_if *brcmf_get_ifp(struct brcmf_pub *drvr, int ifidx)
{
	struct brcmf_if *ifp;
	s32 bsscfgidx;

	if (ifidx < 0 || ifidx >= BRCMF_MAX_IFS) {
		brcmf_err("ifidx %d out of range\n", ifidx);
		return NULL;
	}

	ifp = NULL;
	bsscfgidx = drvr->if2bss[ifidx];
	if (bsscfgidx >= 0)
		ifp = drvr->iflist[bsscfgidx];

	return ifp;
}

static void _brcmf_set_multicast_list(struct work_struct *work)
{
	struct brcmf_if *ifp;
	struct net_device *ndev;
	struct netdev_hw_addr *ha;
	u32 cmd_value, cnt;
	__le32 cnt_le;
	char *buf, *bufp;
	u32 buflen;
	s32 err;

	ifp = container_of(work, struct brcmf_if, multicast_work);

	brcmf_android_wake_lock(ifp->drvr);

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d\n", ifp->bsscfgidx);

	ndev = ifp->ndev;

	/* Determine initial value of allmulti flag */
	cmd_value = (ndev->flags & IFF_ALLMULTI) ? true : false;

	/* Send down the multicast list first. */
	cnt = netdev_mc_count(ndev);
	buflen = sizeof(cnt) + (cnt * ETH_ALEN);
	buf = kmalloc(buflen, GFP_ATOMIC);
	if (!buf) {
		brcmf_android_wake_unlock(ifp->drvr);
		return;
	}
	bufp = buf;

	cnt_le = cpu_to_le32(cnt);
	memcpy(bufp, &cnt_le, sizeof(cnt_le));
	bufp += sizeof(cnt_le);

	netdev_for_each_mc_addr(ha, ndev) {
		if (!cnt)
			break;
		memcpy(bufp, ha->addr, ETH_ALEN);
		bufp += ETH_ALEN;
		cnt--;
	}

	err = brcmf_fil_iovar_data_set(ifp, "mcast_list", buf, buflen);
	if (err < 0) {
		brcmf_err("Setting mcast_list failed, %d\n", err);
		cmd_value = cnt ? true : cmd_value;
	}

	kfree(buf);

	/*
	 * Now send the allmulti setting.  This is based on the setting in the
	 * net_device flags, but might be modified above to be turned on if we
	 * were trying to set some addresses and dongle rejected it...
	 */
	err = brcmf_fil_iovar_int_set(ifp, "allmulti", cmd_value);
	if (err < 0)
		brcmf_err("Setting allmulti failed, %d\n", err);

	/*Finally, pick up the PROMISC flag */
	cmd_value = (ndev->flags & IFF_PROMISC) ? true : false;
	err = brcmf_fil_cmd_int_set(ifp, BRCMF_C_SET_PROMISC, cmd_value);
	if (err < 0)
		brcmf_err("Setting BRCMF_C_SET_PROMISC failed, %d\n",
			  err);

	brcmf_android_wake_unlock(ifp->drvr);
}

#if IS_ENABLED(CONFIG_IPV6)
static void _brcmf_update_ndtable(struct work_struct *work)
{
	struct brcmf_if *ifp;
	int i, ret;

	ifp = container_of(work, struct brcmf_if, ndoffload_work);

	/* clear the table in firmware */
	ret = brcmf_fil_iovar_data_set(ifp, "nd_hostip_clear", NULL, 0);
	if (ret) {
		brcmf_dbg(TRACE, "fail to clear nd ip table err:%d\n", ret);
		return;
	}

	for (i = 0; i < ifp->ipv6addr_idx; i++) {
		ret = brcmf_fil_iovar_data_set(ifp, "nd_hostip",
					       &ifp->ipv6_addr_tbl[i],
					       sizeof(struct in6_addr));
		if (ret)
			brcmf_err("add nd ip err %d\n", ret);
	}
}
#else
static void _brcmf_update_ndtable(struct work_struct *work)
{
}
#endif

static int brcmf_netdev_set_mac_address(struct net_device *ndev, void *addr)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct sockaddr *sa = (struct sockaddr *)addr;
	int err;
#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	struct brcmf_pub *drvr = ifp->drvr;
	bool skip_fw_mac_set = false;

	if ((ifp->bsscfgidx == 0)  && !(brcmf_android_wifi_is_on(drvr)))
		skip_fw_mac_set = true;
#endif

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d\n", ifp->bsscfgidx);

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (!skip_fw_mac_set)
		err = brcmf_fil_iovar_data_set(ifp, "cur_etheraddr", sa->sa_data,
				       ETH_ALEN);
	else
		return 0;
#else
	err = brcmf_fil_iovar_data_set(ifp, "cur_etheraddr", sa->sa_data,
				       ETH_ALEN);
#endif
	if (err < 0) {
		brcmf_err("Setting cur_etheraddr failed, %d\n", err);
	} else {
		brcmf_dbg(TRACE, "updated to %pM\n", sa->sa_data);
		memcpy(ifp->mac_addr, sa->sa_data, ETH_ALEN);
		memcpy(ifp->ndev->dev_addr, ifp->mac_addr, ETH_ALEN);
		ifp->user_mac_set = true;
	}
	return err;
}

static void brcmf_netdev_set_multicast_list(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);

	schedule_work(&ifp->multicast_work);
}

static netdev_tx_t brcmf_netdev_start_xmit(struct sk_buff *skb,
					   struct net_device *ndev)
{
	int ret;
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct ethhdr *eh;
	int head_delta;

	brcmf_dbg(DATA, "Enter, bsscfgidx=%d\n", ifp->bsscfgidx);

	/* Can the device send data? */
	if (drvr->bus_if->state != BRCMF_BUS_UP) {
		brcmf_err("xmit rejected state=%d\n", drvr->bus_if->state);
		netif_stop_queue(ndev);
		dev_kfree_skb(skb);
		ret = -ENODEV;
		goto done;
	}

	/* Make sure there's enough writeable headroom */
	if (skb_headroom(skb) < drvr->hdrlen || skb_header_cloned(skb)) {
		head_delta = max_t(int, drvr->hdrlen - skb_headroom(skb), 0);

		brcmf_dbg(INFO, "%s: insufficient headroom (%d)\n",
			  brcmf_ifname(ifp), head_delta);
		atomic_inc(&drvr->bus_if->stats.pktcowed);
		ret = pskb_expand_head(skb, ALIGN(head_delta, NET_SKB_PAD), 0,
				       GFP_ATOMIC);
		if (ret < 0) {
			brcmf_err("%s: failed to expand headroom\n",
				  brcmf_ifname(ifp));
			atomic_inc(&drvr->bus_if->stats.pktcow_failed);
			goto done;
		}
	}

	/* validate length for ether packet */
	if (skb->len < sizeof(*eh)) {
		ret = -EINVAL;
		dev_kfree_skb(skb);
		goto done;
	}

	eh = (struct ethhdr *)(skb->data);

	if (eh->h_proto == htons(ETH_P_PAE))
		atomic_inc(&ifp->pend_8021x_cnt);

	/* determine the priority */
	if ((skb->priority == 0) || (skb->priority > 7))
		skb->priority = cfg80211_classify8021d(skb, NULL);

	ret = brcmf_proto_tx_queue_data(drvr, ifp->ifidx, skb);
	if (ret < 0)
		brcmf_txfinalize(ifp, skb, false);

done:
	if (ret) {
		ndev->stats.tx_dropped++;
	} else {
		ndev->stats.tx_packets++;
		ndev->stats.tx_bytes += skb->len;
	}

	/* Return ok: we always eat the packet */
	return NETDEV_TX_OK;
}

void brcmf_txflowblock_if(struct brcmf_if *ifp,
			  enum brcmf_netif_stop_reason reason, bool state)
{
	unsigned long flags;

	if (!ifp || !ifp->ndev)
		return;

	brcmf_dbg(TRACE, "enter: bsscfgidx=%d stop=0x%X reason=%d state=%d\n",
		  ifp->bsscfgidx, ifp->netif_stop, reason, state);

	spin_lock_irqsave(&ifp->netif_stop_lock, flags);
	if (state) {
		if (!ifp->netif_stop)
			netif_stop_queue(ifp->ndev);
		ifp->netif_stop |= reason;
	} else {
		ifp->netif_stop &= ~reason;
		if (!ifp->netif_stop)
			netif_wake_queue(ifp->ndev);
	}
	spin_unlock_irqrestore(&ifp->netif_stop_lock, flags);
}

void brcmf_netif_rx(struct brcmf_if *ifp, struct sk_buff *skb)
{
	if (skb->pkt_type == PACKET_MULTICAST)
		ifp->ndev->stats.multicast++;

	if (!(ifp->ndev->flags & IFF_UP)) {
		brcmu_pkt_buf_free_skb(skb);
		return;
	}

	ifp->ndev->stats.rx_bytes += skb->len;
	ifp->ndev->stats.rx_packets++;

#ifdef CPTCFG_NV_CUSTOM_CAP
	/* capture packet histograms before calling netif rx */
	tegra_sysfs_histogram_tcpdump_rx(skb, __func__, __LINE__);
#endif
#ifdef CPTCFG_NV_CUSTOM_STATS
	TEGRA_SYSFS_HISTOGRAM_WAKE_CNT_INC(skb);
#endif
	brcmf_dbg(DATA, "rx proto=0x%X\n", ntohs(skb->protocol));
	if (in_interrupt())
		netif_rx(skb);
	else
		/* If the receive is not processed inside an ISR,
		 * the softirqd must be woken explicitly to service
		 * the NET_RX_SOFTIRQ.  This is handled by netif_rx_ni().
		 */
		netif_rx_ni(skb);
}

static int brcmf_rx_hdrpull(struct brcmf_pub *drvr, struct sk_buff *skb,
			    struct brcmf_if **ifp)
{
	int ret;

	/* process and remove protocol-specific header */
	ret = brcmf_proto_hdrpull(drvr, true, skb, ifp);

	if (ret || !(*ifp) || !(*ifp)->ndev) {
		if (ret != -ENODATA && *ifp)
			(*ifp)->ndev->stats.rx_errors++;
		brcmu_pkt_buf_free_skb(skb);
		return -ENODATA;
	}

	skb->protocol = eth_type_trans(skb, (*ifp)->ndev);
	return 0;
}

void brcmf_rx_frame(struct device *dev, struct sk_buff *skb, bool handle_event)
{
	struct brcmf_if *ifp;
	struct brcmf_bus *bus_if = dev_get_drvdata(dev);
	struct brcmf_pub *drvr = bus_if->drvr;

	brcmf_dbg(DATA, "Enter: %s: rxp=%p\n", dev_name(dev), skb);

	if (brcmf_rx_hdrpull(drvr, skb, &ifp))
		return;

	if (brcmf_proto_is_reorder_skb(skb)) {
		brcmf_proto_rxreorder(ifp, skb);
	} else {
		/* Process special event packets */
		if (handle_event)
			brcmf_fweh_process_skb(ifp->drvr, skb,
					       BCMILCP_SUBTYPE_VENDOR_LONG);

		brcmf_netif_rx(ifp, skb);
	}
}

void brcmf_rx_event(struct device *dev, struct sk_buff *skb)
{
	struct brcmf_if *ifp;
	struct brcmf_bus *bus_if = dev_get_drvdata(dev);
	struct brcmf_pub *drvr = bus_if->drvr;

	brcmf_dbg(EVENT, "Enter: %s: rxp=%p\n", dev_name(dev), skb);

	if (brcmf_rx_hdrpull(drvr, skb, &ifp))
		return;

	brcmf_fweh_process_skb(ifp->drvr, skb, 0);
	brcmu_pkt_buf_free_skb(skb);
}

void brcmf_txfinalize(struct brcmf_if *ifp, struct sk_buff *txp, bool success)
{
	struct ethhdr *eh;
	u16 type;

	if (!ifp) {
		brcmu_pkt_buf_free_skb(txp);
		return;
	}

	eh = (struct ethhdr *)(txp->data);
	type = ntohs(eh->h_proto);

	if (type == ETH_P_PAE) {
		atomic_dec(&ifp->pend_8021x_cnt);
		if (waitqueue_active(&ifp->pend_8021x_wait))
			wake_up(&ifp->pend_8021x_wait);
	}

	if (!success)
		ifp->ndev->stats.tx_errors++;

	brcmu_pkt_buf_free_skb(txp);
}

static void brcmf_ethtool_get_drvinfo(struct net_device *ndev,
				    struct ethtool_drvinfo *info)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	char drev[BRCMU_DOTREV_LEN] = "n/a";

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (!brcmf_android_wifi_is_on(drvr) ||
	    brcmf_android_in_reset(drvr)) {
		brcmf_dbg(INFO, "wifi is not ready\n");
		return;
	}
#endif

	if (drvr->revinfo.result == 0)
		brcmu_dotrev_str(drvr->revinfo.driverrev, drev);
	strlcpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strlcpy(info->version, drev, sizeof(info->version));
	strlcpy(info->fw_version, drvr->fwver, sizeof(info->fw_version));
	strlcpy(info->bus_info, dev_name(drvr->bus_if->dev),
		sizeof(info->bus_info));
}

static const struct ethtool_ops brcmf_ethtool_ops = {
	.get_drvinfo = brcmf_ethtool_get_drvinfo,
};

static int brcmf_netdev_stop(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d\n", ifp->bsscfgidx);

	brcmf_cfg80211_down(ndev);

	brcmf_net_setcarrier(ifp, false);

	return 0;
}

static int brcmf_netdev_open(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_bus *bus_if = drvr->bus_if;
	u32 toe_ol;

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d\n", ifp->bsscfgidx);

	/* If bus is not ready, can't continue */
	if (bus_if->state != BRCMF_BUS_UP) {
		brcmf_err("failed bus is not ready\n");
		return -EAGAIN;
	}

	atomic_set(&ifp->pend_8021x_cnt, 0);

	/* Get current TOE mode from dongle */
	if (brcmf_fil_iovar_int_get(ifp, "toe_ol", &toe_ol) >= 0
	    && (toe_ol & TOE_TX_CSUM_OL) != 0)
		ndev->features |= NETIF_F_IP_CSUM;
	else
		ndev->features &= ~NETIF_F_IP_CSUM;

	if (brcmf_cfg80211_up(ndev)) {
		brcmf_err("failed to bring up cfg80211\n");
		return -EIO;
	}
#if !defined(CPTCFG_BRCMFMAC_ANDROID)
	/* Clear, carrier, set when connected or AP mode. */
	netif_carrier_off(ndev);
#endif /* !defined(CPTCFG_BRCMFMAC_ANDROID) */

	return 0;
}

static const struct net_device_ops brcmf_netdev_ops_pri = {
	.ndo_open = brcmf_android_netdev_open,
	.ndo_stop = brcmf_android_netdev_stop,
	.ndo_do_ioctl = brcmf_android_ioctl_entry,
	.ndo_start_xmit = brcmf_android_netdev_start_xmit,
	.ndo_set_mac_address = brcmf_android_netdev_set_mac_address,
	.ndo_set_rx_mode = brcmf_netdev_set_multicast_list
};

#undef netdev_set_priv_destructor
#if LINUX_VERSION_IS_LESS(4,11,9)
#define netdev_set_priv_destructor(_dev, _destructor) \
	(_dev)->destructor = (_destructor)
#else
#define netdev_set_priv_destructor(_dev, _destructor) \
	(_dev)->priv_destructor = (_destructor)
#endif

#if LINUX_VERSION_IS_LESS(4,12,0)
static void __brcmf_cfg80211_free_netdev(struct net_device *ndev)
{
	brcmf_cfg80211_free_netdev(ndev);
	free_netdev(ndev);
}
#endif

int brcmf_net_attach(struct brcmf_if *ifp, bool rtnl_locked)
{
	struct brcmf_pub *drvr = ifp->drvr;
	struct net_device *ndev;
	s32 err;

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d mac=%pM\n", ifp->bsscfgidx,
		  ifp->mac_addr);
	ndev = ifp->ndev;

	/* set appropriate operations */
	ndev->netdev_ops = &brcmf_netdev_ops_pri;

	ndev->needed_headroom += drvr->hdrlen;
	ndev->ethtool_ops = &brcmf_ethtool_ops;

	/* set the mac address & netns */
	if (!ifp->user_mac_set)
		memcpy(ndev->dev_addr, ifp->mac_addr, ETH_ALEN);
	dev_net_set(ndev, wiphy_net(cfg_to_wiphy(drvr->config)));

	INIT_WORK(&ifp->multicast_work, _brcmf_set_multicast_list);
	INIT_WORK(&ifp->ndoffload_work, _brcmf_update_ndtable);

	if (rtnl_locked)
		err = register_netdevice(ndev);
	else
		err = register_netdev(ndev);
	if (err != 0) {
		brcmf_err("couldn't register the net device\n");
		goto fail;
	}

	netdev_set_priv_destructor(ndev, brcmf_cfg80211_free_netdev);
	brcmf_dbg(INFO, "%s: Broadcom Dongle Host Driver\n", ndev->name);
#ifdef CPTCFG_NV_CUSTOM_SYSFS_TEGRA
	if (ifp->bsscfgidx == 0) {
		dhd_custom_sysfs_tegra_histogram_stat_netdev = ndev;
		if (tegra_sysfs_register(&ndev->dev) < 0)
			brcmf_dbg(INFO, "%s: tegra_sysfs_register() failed\n",
				__func__);
	}
#endif
	return 0;

fail:
	drvr->iflist[ifp->bsscfgidx] = NULL;
	ndev->netdev_ops = NULL;
	return -EBADE;
}

static void brcmf_net_detach(struct net_device *ndev, bool rtnl_locked)
{
	if (ndev->reg_state == NETREG_REGISTERED) {
		if (rtnl_locked)
			unregister_netdevice(ndev);
		else
			unregister_netdev(ndev);
	} else {
		brcmf_cfg80211_free_netdev(ndev);
		free_netdev(ndev);
	}
}

void brcmf_net_setcarrier(struct brcmf_if *ifp, bool on)
{
	struct net_device *ndev;

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d carrier=%d\n", ifp->bsscfgidx,
		  on);

	ndev = ifp->ndev;
	brcmf_txflowblock_if(ifp, BRCMF_NETIF_STOP_REASON_DISCONNECTED, !on);
#if !defined(CPTCFG_BRCMFMAC_ANDROID)
	if (on) {
		if (!netif_carrier_ok(ndev))
			netif_carrier_on(ndev);

	} else {
		if (netif_carrier_ok(ndev))
			netif_carrier_off(ndev);
	}
#endif /* !defined(CPTCFG_BRCMFMAC_ANDROID) */
}

static int brcmf_net_p2p_open(struct net_device *ndev)
{
	brcmf_dbg(TRACE, "Enter\n");

	return brcmf_cfg80211_up(ndev);
}

static int brcmf_net_p2p_stop(struct net_device *ndev)
{
	brcmf_dbg(TRACE, "Enter\n");

	return brcmf_cfg80211_down(ndev);
}

static netdev_tx_t brcmf_net_p2p_start_xmit(struct sk_buff *skb,
					    struct net_device *ndev)
{
	if (skb)
		dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
}

static const struct net_device_ops brcmf_netdev_ops_p2p = {
	.ndo_open = brcmf_android_net_p2p_open,
	.ndo_stop = brcmf_android_net_p2p_stop,
	.ndo_do_ioctl = brcmf_android_ioctl_entry,
	.ndo_start_xmit = brcmf_android_net_p2p_start_xmit
};

static int brcmf_net_p2p_attach(struct brcmf_if *ifp)
{
	struct net_device *ndev;

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d mac=%pM\n", ifp->bsscfgidx,
		  ifp->mac_addr);
	ndev = ifp->ndev;

	ndev->netdev_ops = &brcmf_netdev_ops_p2p;

	/* set the mac address */
	if (!ifp->user_mac_set)
		memcpy(ndev->dev_addr, ifp->mac_addr, ETH_ALEN);

	if (register_netdev(ndev) != 0) {
		brcmf_err("couldn't register the p2p net device\n");
		goto fail;
	}

	brcmf_dbg(INFO, "%s: Broadcom Dongle Host Driver\n", ndev->name);

	return 0;

fail:
	ifp->drvr->iflist[ifp->bsscfgidx] = NULL;
	ndev->netdev_ops = NULL;
	return -EBADE;
}

struct brcmf_if *brcmf_add_if(struct brcmf_pub *drvr, s32 bsscfgidx, s32 ifidx,
			      bool is_p2pdev, const char *name, u8 *mac_addr)
{
	struct brcmf_if *ifp;
	struct net_device *ndev;

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d, ifidx=%d\n", bsscfgidx, ifidx);

	ifp = drvr->iflist[bsscfgidx];
	/*
	 * Delete the existing interface before overwriting it
	 * in case we missed the BRCMF_E_IF_DEL event.
	 */
	if (ifp) {
		if (ifidx) {
			brcmf_err("ERROR: netdev:%s already exists\n",
				  ifp->ndev->name);
			netif_stop_queue(ifp->ndev);
			brcmf_net_detach(ifp->ndev, false);
			drvr->iflist[bsscfgidx] = NULL;
		} else {
			brcmf_dbg(INFO, "netdev:%s ignore IF event\n",
				  ifp->ndev->name);
			return ERR_PTR(-EINVAL);
		}
	}

	if (!drvr->settings->p2p_enable && is_p2pdev) {
		/* this is P2P_DEVICE interface */
		brcmf_dbg(INFO, "allocate non-netdev interface\n");
		ifp = kzalloc(sizeof(*ifp), GFP_KERNEL);
		if (!ifp)
			return ERR_PTR(-ENOMEM);
	} else {
		brcmf_dbg(INFO, "allocate netdev interface\n");
		/* Allocate netdev, including space for private structure */
		ndev = alloc_netdev(sizeof(*ifp), is_p2pdev ? "p2p%d" : name,
				    NET_NAME_UNKNOWN, ether_setup);
		if (!ndev)
			return ERR_PTR(-ENOMEM);

#if LINUX_VERSION_IS_LESS(4,12,0)
		netdev_set_priv_destructor(ndev, __brcmf_cfg80211_free_netdev);
#else
		netdev_set_def_destructor(ndev);
#endif
		ifp = netdev_priv(ndev);
		ifp->ndev = ndev;
		/* store mapping ifidx to bsscfgidx */
		if (drvr->if2bss[ifidx] == BRCMF_BSSIDX_INVALID)
			drvr->if2bss[ifidx] = bsscfgidx;
	}

	ifp->drvr = drvr;
	drvr->iflist[bsscfgidx] = ifp;
	ifp->ifidx = ifidx;
	ifp->bsscfgidx = bsscfgidx;
#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	init_waitqueue_head(&ifp->pend_dev_reset_wait);
#endif
	init_waitqueue_head(&ifp->pend_8021x_wait);
	spin_lock_init(&ifp->netif_stop_lock);

	ifp->user_mac_set = false;
	if (mac_addr != NULL)
		memcpy(ifp->mac_addr, mac_addr, ETH_ALEN);

	brcmf_dbg(TRACE, " ==== pid:%x, if:%s (%pM) created ===\n",
		  current->pid, name, ifp->mac_addr);

	return ifp;
}

static void brcmf_del_if(struct brcmf_pub *drvr, s32 bsscfgidx,
			 bool rtnl_locked)
{
	struct brcmf_if *ifp;

	ifp = drvr->iflist[bsscfgidx];
	drvr->iflist[bsscfgidx] = NULL;
	if (!ifp) {
		brcmf_err("Null interface, bsscfgidx=%d\n", bsscfgidx);
		return;
	}
	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d, ifidx=%d\n", bsscfgidx,
		  ifp->ifidx);
	if (drvr->if2bss[ifp->ifidx] == bsscfgidx)
		drvr->if2bss[ifp->ifidx] = BRCMF_BSSIDX_INVALID;
	if (ifp->ndev) {
		if (bsscfgidx == 0) {
#ifdef CPTCFG_NV_CUSTOM_SYSFS_TEGRA
			tegra_sysfs_unregister(&ifp->ndev->dev);
#endif
			if (ifp->ndev->netdev_ops == &brcmf_netdev_ops_pri) {
				rtnl_lock();
				brcmf_netdev_stop(ifp->ndev);
				rtnl_unlock();
			}
		} else {
			netif_stop_queue(ifp->ndev);
		}

		if (ifp->ndev->netdev_ops == &brcmf_netdev_ops_pri) {
			cancel_work_sync(&ifp->multicast_work);
			cancel_work_sync(&ifp->ndoffload_work);
		}
		brcmf_net_detach(ifp->ndev, rtnl_locked);
	} else {
		/* Only p2p device interfaces which get dynamically created
		 * end up here. In this case the p2p module should be informed
		 * about the removal of the interface within the firmware. If
		 * not then p2p commands towards the firmware will cause some
		 * serious troublesome side effects. The p2p module will clean
		 * up the ifp if needed.
		 */
		brcmf_p2p_ifp_removed(ifp, rtnl_locked);
		kfree(ifp);
	}
}

void brcmf_remove_interface(struct brcmf_if *ifp, bool rtnl_locked)
{
	struct brcmf_pub *drvr;

	if (!ifp || WARN_ON(ifp->drvr->iflist[ifp->bsscfgidx] != ifp))
		return;

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (ifp->bsscfgidx == 0)
		return;
#endif

	brcmf_dbg(TRACE, "Enter, bsscfgidx=%d, ifidx=%d\n", ifp->bsscfgidx,
		  ifp->ifidx);

	drvr = ifp->drvr;

	mutex_lock(&drvr->net_if_lock);
	brcmf_proto_del_if(drvr, ifp);
	brcmf_del_if(drvr, ifp->bsscfgidx, rtnl_locked);
	mutex_unlock(&drvr->net_if_lock);
}

static int brcmf_psm_watchdog_notify(struct brcmf_if *ifp,
				     const struct brcmf_event_msg *evtmsg,
				     void *data)
{
	int err;

	brcmf_dbg(TRACE, "enter: bsscfgidx=%d\n", ifp->bsscfgidx);

	brcmf_err("PSM's watchdog has fired!\n");

	err = brcmf_debug_create_memdump(ifp->drvr->bus_if, data,
					 evtmsg->datalen);
	if (err)
		brcmf_err("Failed to get memory dump, %d\n", err);

	return err;
}

#ifdef CONFIG_INET
#define ARPOL_MAX_ENTRIES	8
static int brcmf_inetaddr_changed(struct notifier_block *nb,
				  unsigned long action, void *data)
{
	struct brcmf_pub *drvr = container_of(nb, struct brcmf_pub,
					      inetaddr_notifier);
	struct in_ifaddr *ifa = data;
	struct net_device *ndev = ifa->ifa_dev->dev;
	struct brcmf_if *ifp;
	int idx, i, ret;
	u32 val;
	__be32 addr_table[ARPOL_MAX_ENTRIES] = {0};

	/* Find out if the notification is meant for us */
	for (idx = 0; idx < BRCMF_MAX_IFS; idx++) {
		ifp = drvr->iflist[idx];
		if (ifp && ifp->ndev == ndev)
			break;
		if (idx == BRCMF_MAX_IFS - 1)
			return NOTIFY_DONE;
	}

	/* check if arp offload is supported */
	ret = brcmf_fil_iovar_int_get(ifp, "arpoe", &val);
	if (ret)
		return NOTIFY_OK;

	/* old version only support primary index */
	ret = brcmf_fil_iovar_int_get(ifp, "arp_version", &val);
	if (ret)
		val = 1;
	if (val == 1)
		ifp = drvr->iflist[0];

	/* retrieve the table from firmware */
	ret = brcmf_fil_iovar_data_get(ifp, "arp_hostip", addr_table,
				       sizeof(addr_table));
	if (ret) {
		brcmf_err("fail to get arp ip table err:%d\n", ret);
		return NOTIFY_OK;
	}

	for (i = 0; i < ARPOL_MAX_ENTRIES; i++)
		if (ifa->ifa_address == addr_table[i])
			break;

	switch (action) {
	case NETDEV_UP:
		if (i == ARPOL_MAX_ENTRIES) {
			brcmf_dbg(TRACE, "add %pI4 to arp table\n",
				  &ifa->ifa_address);
			/* set it directly */
			ret = brcmf_fil_iovar_data_set(ifp, "arp_hostip",
				&ifa->ifa_address, sizeof(ifa->ifa_address));
			if (ret)
				brcmf_err("add arp ip err %d\n", ret);
		}
		break;
	case NETDEV_DOWN:
		if (i < ARPOL_MAX_ENTRIES) {
			addr_table[i] = 0;
			brcmf_dbg(TRACE, "remove %pI4 from arp table\n",
				  &ifa->ifa_address);
			/* clear the table in firmware */
			ret = brcmf_fil_iovar_data_set(ifp, "arp_hostip_clear",
						       NULL, 0);
			if (ret) {
				brcmf_err("fail to clear arp ip table err:%d\n",
					  ret);
				return NOTIFY_OK;
			}
			for (i = 0; i < ARPOL_MAX_ENTRIES; i++) {
				if (addr_table[i] == 0)
					continue;
				ret = brcmf_fil_iovar_data_set(ifp, "arp_hostip",
							       &addr_table[i],
							       sizeof(addr_table[i]));
				if (ret)
					brcmf_err("add arp ip err %d\n",
						  ret);
			}
		}
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}
#endif

#if IS_ENABLED(CONFIG_IPV6)
static int brcmf_inet6addr_changed(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	struct brcmf_pub *drvr = container_of(nb, struct brcmf_pub,
					      inet6addr_notifier);
	struct inet6_ifaddr *ifa = data;
	struct brcmf_if *ifp;
	int i;
	struct in6_addr *table;

	/* Only handle primary interface */
	ifp = drvr->iflist[0];
	if (!ifp)
		return NOTIFY_DONE;
	if (ifp->ndev != ifa->idev->dev)
		return NOTIFY_DONE;

	table = ifp->ipv6_addr_tbl;
	for (i = 0; i < NDOL_MAX_ENTRIES; i++)
		if (ipv6_addr_equal(&ifa->addr, &table[i]))
			break;

	switch (action) {
	case NETDEV_UP:
		if (i == NDOL_MAX_ENTRIES) {
			if (ifp->ipv6addr_idx < NDOL_MAX_ENTRIES) {
				table[ifp->ipv6addr_idx++] = ifa->addr;
			} else {
				for (i = 0; i < NDOL_MAX_ENTRIES - 1; i++)
					table[i] = table[i + 1];
				table[NDOL_MAX_ENTRIES - 1] = ifa->addr;
			}
		}
		break;
	case NETDEV_DOWN:
		if (i < NDOL_MAX_ENTRIES) {
			for (; i < ifp->ipv6addr_idx - 1; i++)
				table[i] = table[i + 1];
			memset(&table[i], 0, sizeof(table[i]));
			ifp->ipv6addr_idx--;
		}
		break;
	default:
		break;
	}

	schedule_work(&ifp->ndoffload_work);

	return NOTIFY_OK;
}
#endif

int brcmf_attach(struct device *dev, struct brcmf_mp_device *settings)
{
	struct brcmf_pub *drvr = NULL;
	int ret = 0;
	int i;

	brcmf_dbg(TRACE, "Enter\n");

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (g_drvr)
		drvr = g_drvr;
	if (!drvr)
#endif
	{
		drvr = kzalloc(sizeof(*drvr), GFP_ATOMIC);
		if (!drvr)
			return -ENOMEM;

		for (i = 0; i < ARRAY_SIZE(drvr->if2bss); i++)
			drvr->if2bss[i] = BRCMF_BSSIDX_INVALID;

		mutex_init(&drvr->proto_block);
		mutex_init(&drvr->net_if_lock);
#ifdef CPTCFG_BRCMFMAC_ANDROID
		/* Attach Android module */
		ret = brcmf_android_attach(drvr);
		if (ret)
			goto fail;
#endif
	}
#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	/* Initialize pkt filter list */
	for (i = 0; i < MAX_PKT_FILTER_COUNT; ++i) {
		drvr->pkt_filter[i].id = 0;
		drvr->pkt_filter[i].enable = 0;
	}
#endif

	/* Link to bus module */
	drvr->hdrlen = 0;
	drvr->bus_if = dev_get_drvdata(dev);
	drvr->bus_if->drvr = drvr;
	drvr->settings = settings;

	/* attach debug facilities */
	brcmf_debug_attach(drvr);

	/* Attach and link in the protocol */
	ret = brcmf_proto_attach(drvr);
	if (ret != 0) {
		brcmf_err("brcmf_prot_attach failed\n");
		goto fail;
	}

	/* Attach to events important for core code */
	brcmf_fweh_register(drvr, BRCMF_E_PSM_WATCHDOG,
			    brcmf_psm_watchdog_notify);

	/* attach firmware event handler */
	brcmf_fweh_attach(drvr);

	return ret;

fail:
	brcmf_detach(dev);

	return ret;
}

static int brcmf_revinfo_read(struct seq_file *s, void *data)
{
	struct brcmf_bus *bus_if = dev_get_drvdata(s->private);
	struct brcmf_rev_info *ri = &bus_if->drvr->revinfo;
	char drev[BRCMU_DOTREV_LEN];
	char brev[BRCMU_BOARDREV_LEN];

	seq_printf(s, "vendorid: 0x%04x\n", ri->vendorid);
	seq_printf(s, "deviceid: 0x%04x\n", ri->deviceid);
	seq_printf(s, "radiorev: %s\n", brcmu_dotrev_str(ri->radiorev, drev));
	seq_printf(s, "chipnum: %u (%x)\n", ri->chipnum, ri->chipnum);
	seq_printf(s, "chiprev: %u\n", ri->chiprev);
	seq_printf(s, "chippkg: %u\n", ri->chippkg);
	seq_printf(s, "corerev: %u\n", ri->corerev);
	seq_printf(s, "boardid: 0x%04x\n", ri->boardid);
	seq_printf(s, "boardvendor: 0x%04x\n", ri->boardvendor);
	seq_printf(s, "boardrev: %s\n", brcmu_boardrev_str(ri->boardrev, brev));
	seq_printf(s, "driverrev: %s\n", brcmu_dotrev_str(ri->driverrev, drev));
	seq_printf(s, "ucoderev: %u\n", ri->ucoderev);
	seq_printf(s, "bus: %u\n", ri->bus);
	seq_printf(s, "phytype: %u\n", ri->phytype);
	seq_printf(s, "phyrev: %u\n", ri->phyrev);
	seq_printf(s, "anarev: %u\n", ri->anarev);
	seq_printf(s, "nvramrev: %08x\n", ri->nvramrev);

	seq_printf(s, "clmver: %s\n", bus_if->drvr->clmver);

	return 0;
}

int brcmf_bus_started(struct device *dev)
{
	int ret = -1;
	struct brcmf_bus *bus_if = dev_get_drvdata(dev);
	struct brcmf_pub *drvr = bus_if->drvr;
	struct brcmf_if *ifp;
	struct brcmf_if *p2p_ifp;

	brcmf_dbg(TRACE, "\n");

	/* add primary networking interface */
#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	ifp = drvr->iflist[0];
#else
	ifp = brcmf_add_if(drvr, 0, 0, false, "wlan%d", NULL);
#endif
	if (IS_ERR(ifp))
		return PTR_ERR(ifp);

	p2p_ifp = NULL;

	/* signal bus ready */
	brcmf_bus_change_state(bus_if, BRCMF_BUS_UP);

	/* Bus is ready, do any initialization */
	ret = brcmf_c_preinit_dcmds(ifp);
	if (ret < 0)
		goto fail;

	brcmf_debugfs_add_entry(drvr, "revinfo", brcmf_revinfo_read);

	/* assure we have chipid before feature attach */
	if (!bus_if->chip) {
		bus_if->chip = drvr->revinfo.chipnum;
		bus_if->chiprev = drvr->revinfo.chiprev;
		brcmf_dbg(INFO, "firmware revinfo: chip %x (%d) rev %d\n",
			  bus_if->chip, bus_if->chip, bus_if->chiprev);
	}
	brcmf_feat_attach(drvr);

	ret = brcmf_proto_init_done(drvr);
	if (ret < 0)
		goto fail;

	brcmf_proto_add_if(drvr, ifp);

	drvr->config = brcmf_cfg80211_attach(drvr, bus_if->dev,
					     drvr->settings->p2p_enable);
	if (drvr->config == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (!ifp->user_mac_set)
		memcpy(ifp->ndev->dev_addr, ifp->mac_addr, ETH_ALEN);
#else
	ret = brcmf_net_attach(ifp, false);
#endif

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (!brcmf_android_in_reset(drvr))
#endif
	{
		if (!ret && drvr->settings->p2p_enable) {
			p2p_ifp = drvr->iflist[1];
			if (p2p_ifp)
				ret = brcmf_net_p2p_attach(p2p_ifp);
		}
	}

	if (ret)
		goto fail;

#ifdef CONFIG_INET
	drvr->inetaddr_notifier.notifier_call = brcmf_inetaddr_changed;
	ret = register_inetaddr_notifier(&drvr->inetaddr_notifier);
	if (ret)
		goto fail;

#if IS_ENABLED(CONFIG_IPV6)
	drvr->inet6addr_notifier.notifier_call = brcmf_inet6addr_changed;
	ret = register_inet6addr_notifier(&drvr->inet6addr_notifier);
	if (ret) {
		unregister_inetaddr_notifier(&drvr->inetaddr_notifier);
		goto fail;
	}
#endif
#endif /* CONFIG_INET */

	return 0;

fail:
	brcmf_err("failed: %d\n", ret);
	if (drvr->config) {
		brcmf_cfg80211_detach(drvr->config);
		drvr->config = NULL;
	}
	brcmf_net_detach(ifp->ndev, false);
	if (p2p_ifp)
		brcmf_net_detach(p2p_ifp->ndev, false);
	drvr->iflist[0] = NULL;
	drvr->iflist[1] = NULL;
	if (drvr->settings->ignore_probe_fail)
		ret = 0;

	return ret;
}

void brcmf_bus_add_txhdrlen(struct device *dev, uint len)
{
	struct brcmf_bus *bus_if = dev_get_drvdata(dev);
	struct brcmf_pub *drvr = bus_if->drvr;

	if (drvr) {
		drvr->hdrlen += len;
	}
}

void brcmf_dev_reset(struct device *dev)
{
	struct brcmf_bus *bus_if = dev_get_drvdata(dev);
	struct brcmf_pub *drvr = bus_if->drvr;

	if (drvr == NULL)
		return;

	if (drvr->iflist[0])
		brcmf_fil_cmd_int_set(drvr->iflist[0], BRCMF_C_TERMINATED, 1);
}

void brcmf_detach(struct device *dev)
{
	s32 i;
	struct brcmf_bus *bus_if = dev_get_drvdata(dev);
	struct brcmf_pub *drvr = bus_if->drvr;

	brcmf_dbg(TRACE, "Enter\n");

	if (drvr == NULL)
		return;

#ifdef CONFIG_INET
	unregister_inetaddr_notifier(&drvr->inetaddr_notifier);
#endif

#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&drvr->inet6addr_notifier);
#endif

	/* stop firmware event handling */
	brcmf_fweh_detach(drvr);
	if (drvr->config)
		brcmf_p2p_detach(&drvr->config->p2p);

	brcmf_bus_change_state(bus_if, BRCMF_BUS_DOWN);

	/* make sure primary interface removed last */
	for (i = BRCMF_MAX_IFS - 1; i > -1; i--)
#ifndef CPTCFG_BRCM_INSMOD_NO_FW
		brcmf_remove_interface(drvr->iflist[i], false);
#else
		brcmf_remove_interface(drvr->iflist[i], true);
#endif

	brcmf_cfg80211_detach(drvr->config);

	brcmf_bus_stop(drvr->bus_if);

	brcmf_proto_detach(drvr);

	brcmf_debug_detach(drvr);
#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	brcmf_dbg(INFO, "not do detach android module\n");
#else
	brcmf_android_detach(drvr);
	bus_if->drvr = NULL;
	kfree(drvr);
#endif
}

s32 brcmf_iovar_data_set(struct device *dev, char *name, void *data, u32 len)
{
	struct brcmf_bus *bus_if = dev_get_drvdata(dev);
	struct brcmf_if *ifp = bus_if->drvr->iflist[0];

	return brcmf_fil_iovar_data_set(ifp, name, data, len);
}

static int brcmf_get_pend_8021x_cnt(struct brcmf_if *ifp)
{
	return atomic_read(&ifp->pend_8021x_cnt);
}

int brcmf_netdev_wait_pend8021x(struct brcmf_if *ifp)
{
	int err;

	err = wait_event_timeout(ifp->pend_8021x_wait,
				 !brcmf_get_pend_8021x_cnt(ifp),
				 MAX_WAIT_FOR_8021X_TX);

	if (!err)
		brcmf_err("Timed out waiting for no pending 802.1x packets\n");

	return !err;
}

void brcmf_bus_change_state(struct brcmf_bus *bus, enum brcmf_bus_state state)
{
	struct brcmf_pub *drvr = bus->drvr;
	struct net_device *ndev;
	int ifidx;

	brcmf_dbg(TRACE, "%d -> %d\n", bus->state, state);
	bus->state = state;

	if (state == BRCMF_BUS_UP) {
		for (ifidx = 0; ifidx < BRCMF_MAX_IFS; ifidx++) {
			if ((drvr->iflist[ifidx]) &&
			    (drvr->iflist[ifidx]->ndev)) {
				ndev = drvr->iflist[ifidx]->ndev;
				if (netif_queue_stopped(ndev))
					netif_wake_queue(ndev);
			}
		}
	}
}

static void brcmf_driver_register(struct work_struct *work)
{
#ifdef CPTCFG_BRCMFMAC_SDIO
	brcmf_sdio_register();
#endif
#ifdef CPTCFG_BRCMFMAC_USB
	brcmf_usb_register();
#endif
#ifdef CPTCFG_BRCMFMAC_PCIE
	brcmf_pcie_register();
#endif
}
static DECLARE_WORK(brcmf_driver_work, brcmf_driver_register);

int __init brcmf_core_init(void)
{
	if (!schedule_work(&brcmf_driver_work))
		return -EBUSY;

	return 0;
}

void __exit brcmf_core_exit(void)
{
	cancel_work_sync(&brcmf_driver_work);

#ifdef CPTCFG_BRCMFMAC_SDIO
	brcmf_sdio_exit();
#endif
#ifdef CPTCFG_BRCMFMAC_USB
	brcmf_usb_exit();
#endif
#ifdef CPTCFG_BRCMFMAC_PCIE
	brcmf_pcie_exit();
#endif
}

int
brcmf_pktfilter_add_remove(struct net_device *ndev, int filter_num, bool add)
{
	struct brcmf_if *ifp =  netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	struct brcmf_pkt_filter_le *pkt_filter;
	int filter_fixed_len = offsetof(struct brcmf_pkt_filter_le, u);
	int pattern_fixed_len = offsetof(struct brcmf_pkt_filter_pattern_le,
				  mask_and_pattern);
	u16 mask_and_pattern[MAX_PKTFILTER_PATTERN_SIZE];
	int buflen = 0;
	int ret = 0;

	brcmf_dbg(INFO, "%s packet filter number %d\n",
		  (add ? "add" : "remove"), filter_num);

	pkt_filter = kzalloc(sizeof(*pkt_filter) +
			(MAX_PKTFILTER_PATTERN_SIZE * 2), GFP_ATOMIC);
	if (!pkt_filter)
		return -ENOMEM;

	switch (filter_num) {
	case BRCMF_UNICAST_FILTER_NUM:
		pkt_filter->id = 100;
		pkt_filter->type = 0;
		pkt_filter->negate_match = 0;
		pkt_filter->u.pattern.offset = 0;
		pkt_filter->u.pattern.size_bytes = 1;
		mask_and_pattern[0] = 0x0001;
		break;
	case BRCMF_BROADCAST_FILTER_NUM:
		//filter_pattern = "101 0 0 0 0xFFFFFFFFFFFF 0xFFFFFFFFFFFF";
		pkt_filter->id = 101;
		pkt_filter->type = 0;
		pkt_filter->negate_match = 0;
		pkt_filter->u.pattern.offset = 0;
		pkt_filter->u.pattern.size_bytes = 6;
		mask_and_pattern[0] = 0xFFFF;
		mask_and_pattern[1] = 0xFFFF;
		mask_and_pattern[2] = 0xFFFF;
		mask_and_pattern[3] = 0xFFFF;
		mask_and_pattern[4] = 0xFFFF;
		mask_and_pattern[5] = 0xFFFF;
		break;
	case BRCMF_MULTICAST4_FILTER_NUM:
		//filter_pattern = "102 0 0 0 0xFFFFFF 0x01005E";
		pkt_filter->id = 102;
		pkt_filter->type = 0;
		pkt_filter->negate_match = 0;
		pkt_filter->u.pattern.offset = 0;
		pkt_filter->u.pattern.size_bytes = 3;
		mask_and_pattern[0] = 0xFFFF;
		mask_and_pattern[1] = 0x01FF;
		mask_and_pattern[2] = 0x5E00;
		break;
	case BRCMF_MULTICAST6_FILTER_NUM:
		//filter_pattern = "103 0 0 0 0xFFFF 0x3333";
		pkt_filter->id = 103;
		pkt_filter->type = 0;
		pkt_filter->negate_match = 0;
		pkt_filter->u.pattern.offset = 0;
		pkt_filter->u.pattern.size_bytes = 2;
		mask_and_pattern[0] = 0xFFFF;
		mask_and_pattern[1] = 0x3333;
		break;
	case BRCMF_MDNS_FILTER_NUM:
		//filter_pattern = "104 0 0 0 0xFFFFFFFFFFFF 0x01005E0000FB";
		pkt_filter->id = 104;
		pkt_filter->type = 0;
		pkt_filter->negate_match = 0;
		pkt_filter->u.pattern.offset = 0;
		pkt_filter->u.pattern.size_bytes = 6;
		mask_and_pattern[0] = 0xFFFF;
		mask_and_pattern[1] = 0xFFFF;
		mask_and_pattern[2] = 0xFFFF;
		mask_and_pattern[3] = 0x0001;
		mask_and_pattern[4] = 0x005E;
		mask_and_pattern[5] = 0xFB00;
		break;
	case BRCMF_ARP_FILTER_NUM:
		//filter_pattern = "105 0 0 12 0xFFFF 0x0806";
		pkt_filter->id = 105;
		pkt_filter->type = 0;
		pkt_filter->negate_match = 0;
		pkt_filter->u.pattern.offset = 12;
		pkt_filter->u.pattern.size_bytes = 2;
		mask_and_pattern[0] = 0xFFFF;
		mask_and_pattern[1] = 0x0608;
		break;
	case BRCMF_BROADCAST_ARP_FILTER_NUM:
		//filter_pattern = "106 0 0 0
		//0xFFFFFFFFFFFF0000000000000806
		//0xFFFFFFFFFFFF0000000000000806";
		pkt_filter->id = 106;
		pkt_filter->type = 0;
		pkt_filter->negate_match = 0;
		pkt_filter->u.pattern.offset = 0;
		pkt_filter->u.pattern.size_bytes = 14;
		mask_and_pattern[0] = 0xFFFF;
		mask_and_pattern[1] = 0xFFFF;
		mask_and_pattern[2] = 0xFFFF;
		mask_and_pattern[3] = 0x0000;
		mask_and_pattern[4] = 0x0000;
		mask_and_pattern[5] = 0x0000;
		mask_and_pattern[6] = 0x0608;
		mask_and_pattern[7] = 0xFFFF;
		mask_and_pattern[8] = 0xFFFF;
		mask_and_pattern[9] = 0xFFFF;
		mask_and_pattern[10] = 0x0000;
		mask_and_pattern[11] = 0x0000;
		mask_and_pattern[12] = 0x0000;
		mask_and_pattern[13] = 0x0608;
		break;
	default:
		ret = -EINVAL;
		goto failed;
	}
	memcpy(pkt_filter->u.pattern.mask_and_pattern, mask_and_pattern,
	       pkt_filter->u.pattern.size_bytes * 2);
	buflen = filter_fixed_len + pattern_fixed_len +
		  pkt_filter->u.pattern.size_bytes * 2;

	if (add) {
		/* Add filter */
		ret = brcmf_fil_iovar_data_set(ifp, "pkt_filter_add",
					       pkt_filter, buflen);
		if (ret)
			goto failed;
		drvr->pkt_filter[filter_num].id = pkt_filter->id;
		drvr->pkt_filter[filter_num].enable  = 0;

	} else {
		/* Delete filter */
		ret = brcmf_fil_iovar_int_set(ifp, "pkt_filter_delete",
					      pkt_filter->id);
		if (ret == -ENOENT)
			ret = 0;
		if (ret)
			goto failed;

		drvr->pkt_filter[filter_num].id = 0;
		drvr->pkt_filter[filter_num].enable  = 0;

	}
failed:
	if (ret)
		brcmf_err("%s packet filter failed, ret=%d\n",
			  (add ? "add" : "remove"), ret);

	kfree(pkt_filter);
	return ret;
}

int brcmf_pktfilter_enable(struct net_device *ndev, bool enable)
{
	struct brcmf_if *ifp =  netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	int ret = 0;
	int idx = 0;

	for (idx = 0; idx < MAX_PKT_FILTER_COUNT; ++idx) {
		if (drvr->pkt_filter[idx].id != 0) {
			drvr->pkt_filter[idx].enable = enable;
			ret = brcmf_fil_iovar_data_set(ifp, "pkt_filter_enable",
						       &drvr->pkt_filter[idx],
				sizeof(struct brcmf_pkt_filter_enable_le));
			if (ret) {
				brcmf_err("%s packet filter id(%d) failed, ret=%d\n",
					  (enable ? "enable" : "disable"),
					  drvr->pkt_filter[idx].id, ret);
			}
		}
	}
	return ret;
}

static struct brcmfmac_platform_data *brcmfmac_pdata;

int brcmf_set_power(bool on, unsigned long msec)
{
	brcmf_dbg(TRACE, "power %s\n", (on ? "on" : "off"));

	if (on && brcmfmac_pdata && brcmfmac_pdata->power_on) {
		brcmfmac_pdata->power_on();
	} else if (!on && brcmfmac_pdata && brcmfmac_pdata->power_off) {
		brcmfmac_pdata->power_off();
	} else {
		if (!wifi_regulator) {
			brcmf_err("cannot get wifi regulator\n");
			return -ENODEV;
		}
		if (on) {
			if (regulator_enable(wifi_regulator)) {
				brcmf_err("WL_REG_ON state unknown, Power off forcely\n");
				regulator_disable(wifi_regulator);
				return -EIO;
			}
#ifdef CPTCFG_BRCMFMAC_NV_GPIO
			/* Power on GPIO */
			if (tegra_toggle_gpio(true, msec) < 0) {
				regulator_disable(wifi_regulator);
				return -EIO;
			}
#endif /* CPTCFG_BRCMFMAC_NV_GPIO */
			msleep(msec);
#ifdef CPTCFG_BRCMFMAC_SDIO
			wifi_card_detect(true);
#endif
#ifdef CPTCFG_BRCMFMAC_PCIE
			brcmf_pcie_register();
#endif
		} else {
#ifdef CPTCFG_BRCMFMAC_SDIO
			wifi_card_detect(false);
#endif
#ifdef CPTCFG_BRCMFMAC_PCIE
			brcmf_pcie_exit();
#endif
#ifdef CPTCFG_BRCMFMAC_NV_GPIO
			/* Power off GPIO */
			if (tegra_toggle_gpio(false, msec) < 0)
				brcmf_err("Cannot disable gpio\n");
#endif /* CPTCFG_BRCMFMAC_NV_GPIO */
			if (regulator_disable(wifi_regulator))
				brcmf_err("Cannot disable wifi regulator\n");
		}
	}

	return 0;
}

static
int brcmf_android_netdev_open(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	struct brcmf_bus *bus_if = drvr->bus_if;
	struct brcmf_android *android = drvr->android;
	u32 timeout;
#endif
	int ret = 0;

	brcmf_android_wake_lock(drvr);

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (ifp->bsscfgidx == 0) {
		if (brcmf_android_wifi_is_on(drvr)) {
			brcmf_err("android wifi is on already\n");
			ret = -EAGAIN;
			goto failed;
		}

		if (brcmf_android_wifi_on(drvr, ndev)) {
			brcmf_err("brcmf_android_wifi_on failed\n");
			ret = -EIO;
			goto failed;
		}

		if (brcmf_android_in_reset(drvr))
			brcmf_dbg(ANDROID, "device reset, wait for bus ready");

		timeout = wait_event_timeout(ifp->pend_dev_reset_wait,
					     !brcmf_android_in_reset(drvr),
					     MAX_WAIT_FOR_BUS_START);

		if (timeout && android->init_done && !android->reset_status) {
			bus_if = drvr->bus_if;
		} else {
			brcmf_err("device reset failed\n");
			brcmf_android_set_reset(ifp->drvr, true);
			brcmf_android_wifi_off(drvr, ndev);
			ret = -EIO;
			goto failed;
		}
	}
failed:
	if (ret) {
#ifdef CPTCFG_NV_CUSTOM_STATS
		TEGRA_SYSFS_HISTOGRAM_STAT_INC(wifi_on_fail);
#endif
		brcmf_android_wake_unlock(drvr);
		return ret;
	}
#endif
	ret = brcmf_netdev_open(ndev);
#ifdef CPTCFG_NV_CUSTOM_SYSFS_TEGRA
	if (ifp->bsscfgidx == 0) {
		tegra_sysfs_on();
#ifdef CPTCFG_NV_CUSTOM_STATS
		if (ret)
			TEGRA_SYSFS_HISTOGRAM_STAT_INC(wifi_on_fail);
		else
			TEGRA_SYSFS_HISTOGRAM_STAT_INC(wifi_on_success);
#endif
	}
#endif

	brcmf_android_wake_unlock(drvr);

	return ret;
}

static
int brcmf_android_netdev_stop(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	struct brcmf_pub *drvr = ifp->drvr;
	int ret;

	brcmf_android_wake_lock(drvr);

	ret = brcmf_netdev_stop(ndev);

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
	if (ifp->bsscfgidx == 0) {
		brcmf_android_wifi_off(ifp->drvr, ndev);
		brcmf_android_set_reset(ifp->drvr, true);
		g_drvr = ifp->drvr;
	}
#endif
#ifdef CPTCFG_NV_CUSTOM_SYSFS_TEGRA
	if (ifp->bsscfgidx == 0) {
		tegra_sysfs_off();
	}
#endif

	brcmf_android_wake_unlock(drvr);

	return ret;
}

static
int brcmf_android_ioctl_entry(struct net_device *net, struct ifreq *ifr,
			      int cmd)
{
	struct brcmf_if *ifp = netdev_priv(net);
	int ret = -EOPNOTSUPP;

	brcmf_android_wake_lock(ifp->drvr);

	if (brcmf_android_is_attached(ifp->drvr)) {
		if (cmd == SIOCDEVPRIVATE + 1)
			ret = brcmf_android_priv_cmd(net, ifr, cmd);
	}

	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static
netdev_tx_t brcmf_android_netdev_start_xmit(struct sk_buff *skb,
					    struct net_device *ndev)
{
	netdev_tx_t ret;
	struct brcmf_if *ifp = netdev_priv(ndev);

#ifdef CPTCFG_NV_CUSTOM_CAP
	tegra_sysfs_histogram_tcpdump_tx(skb, __func__, __LINE__);
#endif
	brcmf_android_wake_lock(ifp->drvr);

	ret = brcmf_netdev_start_xmit(skb, ndev);

	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static
int brcmf_android_netdev_set_mac_address(struct net_device *ndev, void *addr)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	int ret;

	brcmf_android_wake_lock(ifp->drvr);

	ret = brcmf_netdev_set_mac_address(ndev, addr);

	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static
int brcmf_android_net_p2p_open(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	int ret;

	brcmf_android_wake_lock(ifp->drvr);

	ret = brcmf_net_p2p_open(ndev);

	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static
int brcmf_android_net_p2p_stop(struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	int ret;

	brcmf_android_wake_lock(ifp->drvr);

	ret = brcmf_net_p2p_stop(ndev);

	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

static
netdev_tx_t brcmf_android_net_p2p_start_xmit(struct sk_buff *skb,
					     struct net_device *ndev)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	netdev_tx_t ret;

	brcmf_android_wake_lock(ifp->drvr);

	ret = brcmf_net_p2p_start_xmit(skb, ndev);

	brcmf_android_wake_unlock(ifp->drvr);

	return ret;
}

int
brcmf_set_country(struct net_device *ndev, char *country)
{
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	struct wiphy *wiphy = NULL;
	struct brcmf_if *ifp = NULL;
	struct brcmf_fil_country_le ccreq;
	int err;

#ifdef CPTCFG_BRCMFMAC_NV_COUNTRY_CODE
	int i;
#endif /* CPTCFG_BRCMFMAC_NV_COUNTRY_CODE */
	brcmf_dbg(TRACE, "set country: %s\n", country);

	if (!wdev)
		return -ENODEV;

	wiphy = wdev->wiphy;
	ifp = netdev_priv(ndev);

	if (strlen(country) != 2)
		return -EINVAL;

#ifdef CPTCFG_BRCMFMAC_NV_COUNTRY_CODE
	for (i = 0; i < brcmf_mp_global.n_country; i++) {
		if (strncmp(country, brcmf_mp_global.country_code_map[i].country_abbrev, 2) == 0) {
			ccreq.country_abbrev[0] = brcmf_mp_global.country_code_map[i].country_abbrev[0];
			ccreq.country_abbrev[1] = brcmf_mp_global.country_code_map[i].country_abbrev[1];
			ccreq.country_abbrev[2] = 0;
			ccreq.ccode[0] = brcmf_mp_global.country_code_map[i].ccode[0];
			ccreq.ccode[1] = brcmf_mp_global.country_code_map[i].ccode[1];
			ccreq.ccode[2] = 0;
			ccreq.rev = brcmf_mp_global.country_code_map[i].rev;
#ifdef CPTCFG_NV_CUSTOM_STATS
			memcpy(bcmdhd_stat.fw_stat.cur_country_code,
				ccreq.ccode, BRCMF_COUNTRY_BUF_SZ);
#endif
			goto set_country;
		}
	}
#endif /* CPTCFG_BRCMFMAC_NV_COUNTRY_CODE */

	ccreq.country_abbrev[0] = country[0];
	ccreq.country_abbrev[1] = country[1];
	ccreq.country_abbrev[2] = 0;
	ccreq.ccode[0] = country[0];
	ccreq.ccode[1] = country[1];
	ccreq.ccode[2] = 0;
	ccreq.rev = -1;

#ifdef CPTCFG_BRCMFMAC_NV_COUNTRY_CODE
set_country:
#endif /* CPTCFG_BRCMFMAC_NV_COUNTRY_CODE */

	brcmf_dbg(INFO, "set country: %s\n", country);
	err = brcmf_fil_iovar_data_set(ifp, "country", &ccreq, sizeof(ccreq));
	if (err) {
		brcmf_err("Firmware rejected country setting\n");
		return -EINVAL;
	}

	brcmf_setup_wiphybands(wiphy);
	return 0;
}

int
brcmf_start_mkeep_alive(struct net_device *ndev, u8 keep_alive_id,
	u8 *ip_pkt, u16 ip_pkt_len, u8* src_mac, u8* dst_mac, u32 period_msec, u16 ether_type)
{
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	struct brcmf_if *ifp = NULL;
	struct brcmf_mkeep_alive_info *keep_alive_pkt;
	int buf_len = 0;
	int res = -1;
	int len_bytes = 0;
	int i = 0;

	/* ether frame to have both max IP pkt (256 bytes) and ether header */
	char *pmac_frame;

	if (!wdev)
		return -ENODEV;

	ifp = netdev_priv(ndev);
	if (!ifp)
		return -ENODEV;
	/*
	 * The mkeep_alive packet is for STA interface only; if the bss is configured as AP,
	 * dongle shall reject a mkeep_alive request.
	 */
	if (wdev->iftype != NL80211_IFTYPE_STATION) {
		brcmf_err("sta mode not supported \n");
		return res;
	}

	if (ip_pkt_len > MKEEP_ALIVE_IP_PKT_MAX) {
		brcmf_err("failed to start keep alive-Ip packet len is greater than expected \n");
		return res;
	}

	brcmf_dbg(TRACE, "%s execution\n", __FUNCTION__);
	if ((keep_alive_pkt = kzalloc(KEEP_ALIVE_BUF_SIZE, GFP_KERNEL)) == NULL) {
		brcmf_err("mkeep_alive pkt alloc failed\n");
		return -ENOMEM;
	}

	if ((pmac_frame = kzalloc(KEEP_ALIVE_FRAME_SIZE, GFP_KERNEL)) == NULL) {
		brcmf_err("failed to allocate mac_frame with size %d\n", KEEP_ALIVE_FRAME_SIZE);
		res = -ENOMEM;
		goto exit;
	}

	memcpy((char *)keep_alive_pkt, &keep_alive_id, sizeof(keep_alive_id));

	/*
	 * Get current mkeep-alive status.
	 */
	res = brcmf_fil_iovar_data_get(ifp, "mkeep_alive", keep_alive_pkt,
			KEEP_ALIVE_BUF_SIZE);
	if (res) {
		brcmf_err("%s: Get mkeep_alive failed (error=%d)\n", __FUNCTION__, res);
		goto exit;
	} else {
		if (le32_to_cpu(keep_alive_pkt->period_msec != 0)) {
			brcmf_err("%s: Get mkeep_alive failed, ID %u is in use.\n",
				__FUNCTION__, keep_alive_id);
			/* Current occupied ID info */
			brcmf_err("%s: mkeep_alive\n", __FUNCTION__);
			brcmf_err("   Id    : %d\n"
				"   Period: %d msec\n"
				"   Length: %d\n"
				"   Packet: 0x",
				keep_alive_pkt->keep_alive_id,
				le32_to_cpu(keep_alive_pkt->period_msec),
				le16_to_cpu(keep_alive_pkt->len_bytes));

			for (i = 0; i < keep_alive_pkt->len_bytes; i++) {
				brcmf_err("%02x", keep_alive_pkt->data[i]);
			}
			brcmf_err("\n");
			// notfound
			res = -EINVAL;
			goto exit;
		}
	}

	/* Request the specified ID */
	memset(keep_alive_pkt, 0, MAX_KEEP_ALIVE_PKT_SIZE);
	keep_alive_pkt->period_msec = cpu_to_le32(period_msec);
	keep_alive_pkt->version = cpu_to_le16(BRCMF_MKEEP_ALIVE_VERSION);
	keep_alive_pkt->length = cpu_to_le16(BRCMF_MKEEP_ALIVE_FIXED_LEN);

	/* ID assigned */
	keep_alive_pkt->keep_alive_id = keep_alive_id;

	buf_len += BRCMF_MKEEP_ALIVE_FIXED_LEN;

	/*
	 * Build up Ethernet Frame
	 */

	/* Mapping dest mac addr */
	memcpy(pmac_frame, dst_mac, ETH_ALEN);
	pmac_frame += ETH_ALEN;

	/* Mapping src mac addr */
	memcpy(pmac_frame, src_mac, ETH_ALEN);
	pmac_frame += ETH_ALEN;

	if (ether_type == 0) {
		/* Mapping Ethernet type (ETHERTYPE_IP: 0x0800) */
		*(pmac_frame++) = 0x08;
		*(pmac_frame++) = 0x00;
	} else {
		*(pmac_frame) = ether_type;
		/* 2 Octets to be moved */
		pmac_frame += 2;
	}

	/* Mapping IP pkt */
	memcpy(pmac_frame, ip_pkt, ip_pkt_len);
	pmac_frame += ip_pkt_len;

	/*
	 * Length of ether frame (assume to be all hexa bytes)
	 *     = src mac + dst mac + ether type + ip pkt len
	 */
	len_bytes = ETH_ALEN*2 + 2 + ip_pkt_len;
	/* Get back to the beginning. */
	pmac_frame -= len_bytes;
	memcpy(keep_alive_pkt->data, pmac_frame, len_bytes);
	buf_len += len_bytes;
	keep_alive_pkt->len_bytes = cpu_to_le16(len_bytes);

	res = brcmf_fil_iovar_data_set(ifp, "mkeep_alive", keep_alive_pkt, buf_len);

exit:
	kfree(pmac_frame);
	kfree(keep_alive_pkt);
	return res;
}

int
brcmf_stop_mkeep_alive(struct net_device *ndev, u8 keep_alive_id)
{
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	struct brcmf_mkeep_alive_info *keep_alive_pkt;
	int res = -1;
	struct brcmf_if *ifp = NULL;

	if (!wdev)
		return -ENODEV;

	ifp = netdev_priv(ndev);
	if (!ifp)
		return -ENODEV;

	/*
	 * The mkeep_alive packet is for STA interface only; if the bss is configured as AP,
	 * dongle shall reject a mkeep_alive request.
	 */
	if (wdev->iftype != NL80211_IFTYPE_STATION) {
		brcmf_err("sta mode not supported \n");
		return res;
	}
	brcmf_dbg(TRACE,"%s execution\n", __FUNCTION__);

	if ((keep_alive_pkt = kzalloc(KEEP_ALIVE_BUF_SIZE, GFP_KERNEL)) == NULL) {
		brcmf_err("mkeep_alive pkt alloc failed\n");
		return -ENOMEM;
	}

	memcpy((char *)keep_alive_pkt, &keep_alive_id, sizeof(keep_alive_id));

	/*
	 * Get current mkeep-alive status.
	 */
	res = brcmf_fil_iovar_data_get(ifp, "mkeep_alive", keep_alive_pkt,
			KEEP_ALIVE_BUF_SIZE);

	if (res) {
		brcmf_err("%s: Get mkeep_alive failed (error=%d)\n", __FUNCTION__, res);
		goto exit;
	}

	/* Make it stop if available */
	if (le32_to_cpu(keep_alive_pkt->period_msec != 0)) {
		brcmf_dbg(INFO,"stop mkeep_alive on ID %d\n", keep_alive_id);
		memset(keep_alive_pkt, 0, MAX_KEEP_ALIVE_PKT_SIZE);
		keep_alive_pkt->period_msec = 0;
		keep_alive_pkt->version = cpu_to_le16(BRCMF_MKEEP_ALIVE_VERSION);
		keep_alive_pkt->length = cpu_to_le16(BRCMF_MKEEP_ALIVE_FIXED_LEN);
		keep_alive_pkt->keep_alive_id = keep_alive_id;
		res = brcmf_fil_iovar_data_set(ifp, "mkeep_alive", keep_alive_pkt,
				sizeof(struct brcmf_mkeep_alive_info));
	} else {
		brcmf_err("%s: Keep alive ID %u does not exist.\n", __FUNCTION__,
				keep_alive_id);
		res = -EINVAL;
	}
exit:
	kfree(keep_alive_pkt);
	return res;
}

int brcmf_android_priv_cmd(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
	struct brcmf_if *ifp = netdev_priv(ndev);
	int ret = 0;
	char *command = NULL;
	int bytes_written = 0;
	struct brcmf_android_wifi_priv_cmd priv_cmd;

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		compat_brcmf_android_wifi_priv_cmd compat_priv_cmd;
		if (copy_from_user(&compat_priv_cmd, ifr->ifr_data,
			sizeof(compat_brcmf_android_wifi_priv_cmd))) {
			ret = -EFAULT;
			goto exit;
		}
		priv_cmd.buf = compat_ptr(compat_priv_cmd.buf);
		priv_cmd.used_len = compat_priv_cmd.used_len;
		priv_cmd.total_len = compat_priv_cmd.total_len;
	} else
#endif /* CONFIG_COMPAT */
	{
		if (copy_from_user(&priv_cmd, ifr->ifr_data,
			   sizeof(struct brcmf_android_wifi_priv_cmd))) {
			ret = -EFAULT;
			goto exit;
		}
	}

	if (priv_cmd.total_len > PRIVATE_COMMAND_MAX_LEN ||
	    priv_cmd.total_len < 0) {
		brcmf_err("too long priavte command\n");
		ret = -EINVAL;
		goto exit;
	}
	command = kmalloc((priv_cmd.total_len + 1), GFP_KERNEL);
	if (!command) {
		ret = -ENOMEM;
		goto exit;
	}
	if (copy_from_user(command, priv_cmd.buf, priv_cmd.total_len)) {
		ret = -EFAULT;
		goto exit;
	}

	command[priv_cmd.total_len] = '\0';

	brcmf_dbg(INFO, "Android private cmd \"%s\" on %s\n",
		  command, ifr->ifr_name);

	bytes_written = brcmf_handle_private_cmd(ifp->drvr, ndev, command,
						 priv_cmd.total_len);

	if (bytes_written >= 0) {
		if (bytes_written == 0 && priv_cmd.total_len > 0)
			command[0] = '\0';
		if (bytes_written >= priv_cmd.total_len) {
			brcmf_err("bytes_written = %d\n", bytes_written);
			bytes_written = priv_cmd.total_len;
		} else {
			bytes_written++;
		}
		priv_cmd.used_len = bytes_written;
		if (copy_to_user(priv_cmd.buf, command, bytes_written)) {
			brcmf_err("failed to copy data to user buffer\n");
			ret = -EFAULT;
		}
	} else {
		ret = bytes_written;
	}

exit:
	kfree(command);
	return ret;
}

#ifdef CPTCFG_BRCM_INSMOD_NO_FW
void brcmf_wake_dev_reset_waitq(struct brcmf_pub *drvr, int status)
{
	struct brcmf_if *ifp = drvr->iflist[0];

	drvr->android->reset_status = status;
	/* wake up device reset wait queue */
	if (waitqueue_active(&ifp->pend_dev_reset_wait)) {
		brcmf_dbg(INFO, "device reset is done, wake up pending task\n");
		brcmf_android_set_reset(drvr, false);
		wake_up(&ifp->pend_dev_reset_wait);
	}
}
#endif
