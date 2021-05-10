TARGET := iphone:clang:14.3:7.0
ARCH = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TOOL_NAME = fouldecrypt flexdecrypt2

fouldecrypt_FILES = main.m
fouldecrypt_CFLAGS = -fobjc-arc
fouldecrypt_CODESIGN_FLAGS = -Sentitlements.plist
fouldecrypt_INSTALL_PATH = /usr/local/bin

flexdecrypt2_FILES = flexwrapper.m
flexdecrypt2_CFLAGS = -fobjc-arc
flexdecrypt2_CODESIGN_FLAGS = -Sentitlements.plist
flexdecrypt2_INSTALL_PATH = /usr/local/bin


include $(THEOS_MAKE_PATH)/tool.mk
