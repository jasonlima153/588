TARGET := iphone:clang:latest:15.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := OctopusIMMultiPush

OctopusIMMultiPush_FILES := Tweak.xm
OctopusIMMultiPush_CFLAGS := -fobjc-arc -Wno-deprecated-declarations
OctopusIMMultiPush_FRAMEWORKS := UIKit Security AVFoundation

include $(THEOS)/makefiles/tweak.mk
