TARGET := iphone:clang:14.5:13.0
ARCHS = arm64 arm64e
export ADDITIONAL_CFLAGS = -DTHEOS_LEAN_AND_MEAN -fobjc-arc

include $(THEOS)/makefiles/common.mk

TOOL_NAME = fouldecrypt flexdecrypt2 foulwrapper

# export USE_TFP0 = 1
export USE_LIBKRW = 1
# export USE_LIBKERNRW = 1

fouldecrypt_FILES = main.cpp foulmain.cpp
fouldecrypt_CFLAGS = -fobjc-arc -Wno-unused-variable # -Ipriv_include
fouldecrypt_CCFLAGS = $(fouldecrypt_CFLAGS)
fouldecrypt_CODESIGN_FLAGS = -Sentitlements.plist
fouldecrypt_INSTALL_PATH = /usr/local/bin
fouldecrypt_SUBPROJECTS = kerninfra
fouldecrypt_LDFLAGS += -Lkerninfra/libs
fouldecrypt_CCFLAGS += -std=c++2a

flexdecrypt2_FILES = main.cpp flexwrapper.cpp
flexdecrypt2_CFLAGS = -fobjc-arc -Wno-unused-variable # -Ipriv_include
flexdecrypt2_CCFLAGS = $(flexdecrypt2_CFLAGS)
flexdecrypt2_CODESIGN_FLAGS = -Sentitlements.plist
flexdecrypt2_INSTALL_PATH = /usr/local/bin
flexdecrypt2_SUBPROJECTS = kerninfra
flexdecrypt2_LDFLAGS += -Lkerninfra/libs
flexdecrypt2_CCFLAGS += -std=c++2a

foulwrapper_FILES = foulwrapper.m
foulwrapper_CFLAGS = -fobjc-arc -Wno-unused-variable -Iinclude
foulwrapper_CCFLAGS = $(foulwrapper_CFLAGS)
foulwrapper_CODESIGN_FLAGS = -Sentitlements.plist
foulwrapper_INSTALL_PATH = /usr/local/bin
foulwrapper_FRAMEWORKS = Foundation MobileCoreServices
foulwrapper_PRIVATE_FRAMEWORKS = MobileContainerManager

include $(THEOS_MAKE_PATH)/tool.mk
