TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WebViewProxy

WebViewProxy_FILES = Tweak.x
WebViewProxy_CFLAGS = -fobjc-arc
WebViewProxy_FRAMEWORKS = Foundation UIKit WebKit SystemConfiguration CFNetwork

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 WebViewProxy 2>/dev/null; killall -9 com.apple.WebKit.Networking 2>/dev/null; killall -9 fluxdo 2>/dev/null; true"

