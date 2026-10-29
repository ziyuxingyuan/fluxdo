// WebViewProxy - 让 FluxDo 的 WKWebView 走它自己的本地 DoH 代理
// 适用: Dopamine (rootless) iOS 15.0 - 16.6.1
//
// 原理:
//   FluxDo 用 Rust (doh_proxy) 在 127.0.0.1 上起一个 HTTP CONNECT 代理,
//   端口运行时随机分配。App 自己的 Dart 请求已经走它, 但 WKWebView 的请求
//   跑在独立的 com.apple.WebKit.Networking 进程里, 拿不到这份配置。
//   本插件做两件事:
//     1) 在 FluxDo 进程里枚举自己的 LISTEN socket, 找出代理端口,
//        写进 CFPreferences 域 com.fluxdo.webviewproxy 的 DetectedPort
//     2) 在 WebKit 网络进程里 hook NSURLSessionConfiguration 与
//        SCDynamicStoreCopyProxies, 强制返回这个代理
//
// 前提:
//   FluxDo 的代理对 CONNECT 做 TLS 解密(MITM), 必须先把它的 CA 证书装进
//   系统信任库, 否则所有 HTTPS 都会报证书错误。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <sys/time.h>

#define WVP_DOMAIN   CFSTR("com.fluxdo.webviewproxy")
#define WVP_LOG_PATH @"/var/mobile/Library/Logs/WebViewProxy.log"
#define WVP_APP_BID  @"com.github.lingyan000.fluxdo"

// 日志: 依次尝试多个位置, 哪个真能写就用哪个
//   1) 进程容器内的 tmp/      (沙盒内必定可写)
//   2) /var/mobile/Library/Logs/  (越权运行的进程)
//   3) /tmp/
static NSString *WVPWriteLine(NSString *path, NSString *line) {
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [path stringByDeletingLastPathComponent];
    if (![fm fileExistsAtPath:dir])
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    if (![fm fileExistsAtPath:path])
        [fm createFileAtPath:path contents:nil attributes:nil];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) return nil;                    // 沙盒拒绝打开 -> 换下一个候选
    @try {
        [fh seekToEndOfFile];
        [fh writeData:data];
        [fh closeFile];
        return path;
    } @catch (NSException *e) {
        @try { [fh closeFile]; } @catch (NSException *e2) {}
        return nil;
    }
}

static void WVPLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[WebViewProxy] %@", msg);       // 系统日志兜底, 不受沙盒限制

    static NSArray *cands = nil;
    static NSUInteger idx = 0;
    static BOOL announced = NO;
    if (!cands) {
        NSMutableArray *a = [NSMutableArray array];
        NSString *tmp = NSTemporaryDirectory();
        if (tmp.length) [a addObject:[tmp stringByAppendingPathComponent:@"WebViewProxy.log"]];
        [a addObject:@"/var/mobile/Library/Logs/WebViewProxy.log"];
        [a addObject:@"/tmp/WebViewProxy.log"];
        cands = [a copy];
    }
    NSString *stamp = [NSString stringWithFormat:@"[%@] [pid %d] ", [NSDate date], getpid()];
    while (idx < cands.count) {
        NSString *path = cands[idx];
        if (WVPWriteLine(path, [stamp stringByAppendingFormat:@"%@\n", msg])) {
            if (!announced) {
                announced = YES;
                WVPWriteLine(path, [stamp stringByAppendingFormat:@"日志落盘于 %@ (候选 %lu 个)\n",
                                    path, (unsigned long)cands.count]);
            }
            return;
        }
        idx++;
    }
}

static id WVPGet(NSString *key) {
    CFPropertyListRef v = CFPreferencesCopyAppValue((__bridge CFStringRef)key, WVP_DOMAIN);
    return v ? CFBridgingRelease(v) : nil;
}

static void WVPut(NSString *key, id value) {
    CFPreferencesSetAppValue((__bridge CFStringRef)key, (__bridge CFPropertyListRef)value, WVP_DOMAIN);
    CFPreferencesAppSynchronize(WVP_DOMAIN);
}

static BOOL WVPEnabled(void) {
    id v = WVPGet(@"Enabled");
    return v ? [v boolValue] : YES;
}

static int WVPActivePort(void) {
    int p = [WVPGet(@"Port") intValue];
    if (p > 0 && p < 65536) return p;            // 手填优先
    return [WVPGet(@"DetectedPort") intValue];   // 否则用探测值
}

static NSString *WVPProxyHost(void) {
    NSString *h = WVPGet(@"Host");
    return h.length ? h : @"127.0.0.1";
}

// 本地端口是否真的在监听 (本地 connect, 阻塞极短)
static BOOL WVPPortAlive(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NO;
    struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 80000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return r == 0;
}

// 只对这些域名走代理, 其余 DIRECT
static NSString *WVPPAC(int port, NSString *proxyHost) {
    static NSString *cached = nil;
    static int cachedPort = -1;
    if (cached && cachedPort == port) return cached;
    id domains = WVPGet(@"Domains");
    NSArray *suffixes = [domains isKindOfClass:[NSArray class]]
        ? (NSArray *)domains : @[@"linux.do"];
    NSMutableString *js = [NSMutableString stringWithString:@"function FindProxyForURL(url, host) {"];
    for (NSString *d in suffixes) {
        [js appendFormat:@"  if (host == '%@' || dnsDomainIs(host, '.%@')) return 'PROXY %@:%d; DIRECT';",
            d, d, proxyHost, port];
    }
    [js appendString:@"  return 'DIRECT';\n}"];
    cached = [js copy];
    cachedPort = port;
    return cached;
}

static NSDictionary *WVPProxyDict(void) {
    static NSDictionary *cache = nil;
    static time_t lastCheck = 0;
    static int lastWarnPort = -1;
    time_t now = time(NULL);
    if (cache && now - lastCheck < 2) return cache;
    lastCheck = now;
    cache = nil;

    if (!WVPEnabled()) return nil;

    int port = WVPActivePort();
    if (port <= 0 || port > 65535) return nil;

    // 端口必须真的在监听, 否则 FluxDo 没开代理时会把别人的 WebView 打瘫
    if (!WVPPortAlive(port)) {
        if (lastWarnPort != port) {
            WVPLog(@"端口 %d 无监听, 暂不接管", port);
            lastWarnPort = port;
        }
        return nil;
    }
    lastWarnPort = -1;

    NSString *host = WVPProxyHost();
    NSString *mode = WVPGet(@"Mode");
    if (![mode isEqualToString:@"global"]) {
        // PAC 模式: 只让指定域名走代理, 其余直连
        cache = @{
            @"ProxyAutoConfigEnable": @YES,
            @"ProxyAutoConfigJavaScript": WVPPAC(port, host),
        };
    } else {
        NSNumber *pnum = @(port);
        cache = @{
            @"HTTPEnable":  @YES,
            @"HTTPProxy":   host,
            @"HTTPPort":    pnum,
            @"HTTPSEnable": @YES,
            @"HTTPSProxy":  host,
            @"HTTPSPort":   pnum,
            @"ExceptionsList":
                @[@"127.0.0.1", @"localhost", @"::1"],
        };
    }
    return cache;
}

static BOOL gIsApp = NO;

#pragma mark - Hooks

// FluxDo 进程: 本地代理 listen() 时顺手抓到端口
%hookf(int, listen, int sockfd, int backlog) {
    int r = %orig;
    if (r == 0 && gIsApp) {
        struct sockaddr_in a; socklen_t len = sizeof(a);
        memset(&a, 0, sizeof(a));
        if (getsockname(sockfd, (struct sockaddr *)&a, &len) == 0 && a.sin_family == AF_INET) {
            int port = ntohs(a.sin_port);
            BOOL loopback = (ntohl(a.sin_addr.s_addr) == INADDR_LOOPBACK);
            if (loopback && port > 1024 && port < 65535 &&
                port != 8181 && port != 50300 && port != 50301) {
                if ([WVPGet(@"DetectedPort") intValue] != port) {
                    WVPut(@"DetectedPort", @(port));
                    WVPLog(@"捕获本地监听端口 %d", port);
                }
            }
        }
    }
    return r;
}

%hook NSURLSessionConfiguration

- (NSDictionary *)connectionProxyDictionary {
    NSDictionary *p = WVPProxyDict();
    if (p) return p;
    return %orig;
}

+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
    NSURLSessionConfiguration *c = %orig();
    NSDictionary *p = WVPProxyDict();
    if (p) c.connectionProxyDictionary = p;
    return c;
}

+ (NSURLSessionConfiguration *)ephemeralSessionConfiguration {
    NSURLSessionConfiguration *c = %orig();
    NSDictionary *p = WVPProxyDict();
    if (p) c.connectionProxyDictionary = p;
    return c;
}

%end

%hook WKWebView

- (instancetype)initWithFrame:(CGRect)frame configuration:(WKWebViewConfiguration *)configuration {
    NSDictionary *p = WVPProxyDict();
    WVPLog(@"新建 WebView, 当前代理端口 %d", p ? WVPActivePort() : 0);
    return %orig;
}

- (instancetype)initWithCoder:(NSCoder *)coder {
    return %orig;
}

%end

%ctor {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    BOOL isApp = [bid isEqualToString:WVP_APP_BID];
    WVPLog(@"loaded into %@ (pid %d, app=%d)", bid ?: @"?", getpid(), isApp);

    if (isApp) {
        gIsApp = YES;
        WVPLog(@"App 进程已就绪, 等待 listen()");
    } else {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            WVPLog(@"网络进程读到端口 %d", WVPActivePort());
        });
    }
}
