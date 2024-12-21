LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_PREBUILT_KERNEL),)
CYPRESS-FMAC_PATH := kernel/nvidia/cypress-fmac

include $(CLEAR_VARS)

LOCAL_MODULE        := cypress-fmac
LOCAL_MODULE_SUFFIX := .ko
LOCAL_MODULE_CLASS  := ETC
LOCAL_MODULE_PATH   := $(TARGET_OUT_VENDOR)/lib/modules

_fmac_intermediates := $(call intermediates-dir-for,$(LOCAL_MODULE_CLASS),$(LOCAL_MODULE))
_fmac_ko := $(_fmac_intermediates)/$(LOCAL_MODULE)$(LOCAL_MODULE_SUFFIX)
KERNEL_OUT := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ
KERNEL_OUT_RELATIVE := ../../KERNEL_OBJ

$(_fmac_ko): $(KERNEL_OUT)/arch/$(KERNEL_ARCH)/boot/$(BOARD_KERNEL_IMAGE_NAME)
	@mkdir -p $(dir $@)
	@mkdir -p $(KERNEL_MODULES_OUT)/lib/modules
	@cp -R $(CYPRESS-FMAC_PATH)/backports-wireless/* $(_fmac_intermediates)/
	@chmod +x $(_fmac_intermediates)/kconf/lxdialog/check-lxdialog.sh
	$(hide) +$(KERNEL_MAKE_CMD) $(KERNEL_MAKE_FLAGS) -C $(_fmac_intermediates) ARCH=$(KERNEL_ARCH) $(KERNEL_CROSS_COMPILE) KLIB=$(KERNEL_MODULES_OUT)/lib/modules KLIB_BUILD=$(KERNEL_OUT_RELATIVE) defconfig-brcmfmac
	$(hide) +$(KERNEL_MAKE_CMD) $(KERNEL_MAKE_FLAGS) -C $(_fmac_intermediates) ARCH=$(KERNEL_ARCH) $(KERNEL_CROSS_COMPILE) KLIB=$(KERNEL_MODULES_OUT)/lib/modules KLIB_BUILD=$(KERNEL_OUT_RELATIVE) modules
	modules=$$(find $(_fmac_intermediates) -type f -name '*.ko'); \
	for f in $$modules; do \
		$(KERNEL_TOOLCHAIN_PATH)strip --strip-unneeded $$f; \
		cp $$f $(KERNEL_MODULES_OUT)/lib/modules; \
	done;
	touch $(_fmac_intermediates)/cypress-fmac.ko

include $(BUILD_SYSTEM)/base_rules.mk
endif
