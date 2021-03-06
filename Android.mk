LOCAL_PATH := $(call my-dir)

CYPRESS-FMAC_PATH := kernel/nvidia/cypress-fmac

include $(CLEAR_VARS)

LOCAL_MODULE               := cypress-fmac
LOCAL_MODULE_SUFFIX        := .ko
LOCAL_MODULE_RELATIVE_PATH := modules
LOCAL_MODULE_CLASS         := SHARED_LIBRARIES
LOCAL_MULTILIB             := 32
LOCAL_VENDOR_MODULE        := true

_fmac_intermediates := $(call intermediates-dir-for,$(LOCAL_MODULE_CLASS),$(LOCAL_MODULE))
_fmac_ko := $(_fmac_intermediates)/$(LOCAL_MODULE)$(LOCAL_MODULE_SUFFIX)
KERNEL_OUT := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ

$(_fmac_ko): $(KERNEL_OUT)/arch/$(KERNEL_ARCH)/boot/$(BOARD_KERNEL_IMAGE_NAME)
	@mkdir -p $(dir $@)
	@mkdir -p $(KERNEL_MODULES_OUT)/lib/modules
	@cp -R $(CYPRESS-FMAC_PATH)/backports-wireless/* $(_fmac_intermediates)/
	$(hide) +$(MAKE) -C $(_fmac_intermediates) ARCH=arm64 $(KERNEL_CROSS_COMPILE) KLIB=$(KERNEL_MODULES_OUT)/lib/modules KLIB_BUILD=$(KERNEL_OUT) defconfig-brcmfmac
	$(hide) +$(MAKE) -C $(_fmac_intermediates) ARCH=arm64 $(KERNEL_CROSS_COMPILE) KLIB=$(KERNEL_MODULES_OUT)/lib/modules KLIB_BUILD=$(KERNEL_OUT) modules
	modules=$$(find $(_fmac_intermediates) -type f -name '*.ko'); \
	for f in $$modules; do \
		$(KERNEL_TOOLCHAIN_PATH)strip --strip-unneeded $$f; \
		cp $$f $(KERNEL_MODULES_OUT)/lib/modules; \
	done;
	touch $(_fmac_intermediates)/cypress-fmac.ko

include $(BUILD_SYSTEM)/base_rules.mk
