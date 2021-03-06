#
# Makefile fragment for Broadcom 802.11n Networking Device Driver
#
# Copyright (c) 2010 Broadcom Corporation
# Copyright (C) 2018-2019 NVIDIA Corporation. All rights reserved.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

ccflags-y += \
	-I$(backport_srctree)/drivers/net/wireless/broadcom/brcm80211/brcmfmac	\
	-I$(backport_srctree)/drivers/net/wireless/broadcom/brcm80211/include \
	-I$(backport_srctree)/drivers/net/wireless/broadcom/brcm80211/brcmfmac/nv \
	-DCPTCFG_BRCMFMAC_NV_GPIO \
	-DCPTCFG_BRCMFMAC_NV_CUSTOM_MAC \
	-DCPTCFG_BRCMFMAC_NV_CUSTOM_FILES \
	-DCPTCFG_BRCMFMAC_NV_COUNTRY_CODE

obj-$(CPTCFG_BRCMFMAC) += brcmfmac.o
brcmfmac-objs += \
		cfg80211.o \
		chip.o \
		fwil.o \
		fweh.o \
		p2p.o \
		proto.o \
		common.o \
		core.o \
		firmware.o \
		feature.o \
		btcoex.o \
		vendor.o \
		pno.o
brcmfmac-$(CPTCFG_BRCMFMAC_PROTO_BCDC) += \
		bcdc.o \
		fwsignal.o
brcmfmac-$(CPTCFG_BRCMFMAC_PROTO_MSGBUF) += \
		commonring.o \
		flowring.o \
		msgbuf.o
brcmfmac-$(CPTCFG_BRCMFMAC_SDIO) += \
		sdio.o \
		bcmsdh.o
brcmfmac-$(CPTCFG_BRCMFMAC_USB) += \
		usb.o
brcmfmac-$(CPTCFG_BRCMFMAC_PCIE) += \
		pcie.o
brcmfmac-$(CPTCFG_BRCMDBG) += \
		debug.o
brcmfmac-$(CPTCFG_BRCM_TRACING) += \
		tracepoint.o
brcmfmac-$(CONFIG_OF) += \
		of.o
brcmfmac-$(CPTCFG_BRCMFMAC_ANDROID) += \
		android.o \
		nv/nv_common.o

ifneq ($(CPTCFG_NV_CUSTOM_SYSFS_TEGRA),)
brcmfmac-$(CPTCFG_NV_CUSTOM_SYSFS_TEGRA) += \
	nv/nv_custom_sysfs_tegra.o
ccflags-y += \
	-DCPTCFG_NV_CUSTOM_SYSFS_TEGRA
endif

ifneq ($(CPTCFG_NV_CUSTOM_CAP),)
brcmfmac-$(CPTCFG_NV_CUSTOM_CAP) += \
	nv/nv_ping.o \
	nv/nv_rssi.o \
	nv/nv_tcpdump.o
ccflags-y += \
	-DCPTCFG_NV_CUSTOM_CAP
endif

ifneq ($(CPTCFG_BRCMFMAC_NV_IDS),)
brcmfmac-$(CPTCFG_BRCMFMAC_NV_IDS) += \
    nv/nv_logger.o
ccflags-y += \
    -DCPTCFG_BRCMFMAC_NV_IDS
endif

ifneq ($(CPTCFG_NV_CUSTOM_SCAN),)
brcmfmac-$(CPTCFG_NV_CUSTOM_SCAN) += \
	nv/nv_scan.o
ccflags-y += \
	-DCPTCFG_NV_CUSTOM_SCAN
endif

ifneq ($(CPTCFG_NV_NET_BW_EST_TEGRA),)
brcmfmac-$(CPTCFG_NV_NET_BW_EST_TEGRA) += \
	nv/dhd_custom_net_bw_est_tegra.o
ccflags-y += \
	-DCPTCFG_BRCMFMAC_NV_NET_BW_EST_TEGRA
endif

ifneq ($(CPTCFG_NV_NET_DIAG_TEGRA),)
brcmfmac-$(CPTCFG_NV_NET_DIAG_TEGRA) += \
		nv/dhd_custom_net_diag_tegra.o
ccflags-y += \
	-DCPTCFG_BRCMFMAC_NV_NET_DIAG_TEGRA
endif

ifneq ($(CPTCFG_NV_CUSTOM_RF_TEST),)
brcmfmac-$(CPTCFG_NV_CUSTOM_RF_TEST) += \
	nv/nv_rf_test.o
ccflags-y += \
	-DCPTCFG_NV_CUSTOM_RF_TEST
endif

ifneq ($(CPTCFG_NV_CUSTOM_STATS),)
brcmfmac-$(CPTCFG_NV_CUSTOM_STATS) += \
	nv/nv_stats.o
ccflags-y += \
	-DCPTCFG_NV_CUSTOM_STATS
endif

ifneq ($(CPTCFG_BRCMFMAC_NV_PRIV_CMD),)
brcmfmac-$(CPTCFG_BRCMFMAC_NV_PRIV_CMD) += \
	nv/nv_android.o
ccflags-y += \
	-DCPTCFG_BRCMFMAC_NV_PRIV_CMD
endif

ifneq ($(CPTCFG_NV_CUSTOM_ROAM_OFF),)
ccflags-y += \
	-DCPTCFG_NV_CUSTOM_ROAM_OFF
endif

ifneq ($(CPTCFG_NV_DEBUG),)
brcmfmac-$(CPTCFG_NV_DEBUG) += \
	nv/nv_debug.o
ccflags-y += \
	-DCPTCFG_NV_DEBUG
endif
