TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WebViewProxy

WebViewProxy_FILES = Tweak.x
WebViewProxy_CFLAGS = -fobjc-arc
WebViewProxy_FRAMEWORKS = Foundation UIKit WebKit SystemConfiguration

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 Runner; killall -9 com.apple.WebKit.Networking || true"
