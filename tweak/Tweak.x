// WebViewProxy 0.1.5 - 让 FluxDo 的 WKWebView 走它自己的本地 DoH 代理
// 适用: Dopamine (rootless) iOS 15.0 - 16.6.1
//
// 0.1.4 相比 0.1.1 的改动:
//   1) filter plist 改用 Executables 匹配 com.apple.WebKit.Networking
//      (XPC 服务不走 Bundles 匹配, 之前从未注入成功)
//   2) 放弃 NSURLSessionConfiguration.connectionProxyDictionary,
//      WKWebView 不创建 NSURLSessionConfiguration, 改为 hook
//      CFNetworkCopySystemProxySettings (CFNetwork 真正读系统代理的入口;
//      SCDynamicStoreCopyProxies 在 iOS SDK 里 unavailable, 不能用)
//   3) 解决跨进程端口传递: CFPreferences 按 App 容器隔离, WebKit 进程
//      读不到 App 探测出的端口。改为 App 进程内起一个固定端口(65530)的
//      TCP 转发器, WebKit 侧硬编码连它; App 退出转发器即消失, 天然兜底。
//   4) 域名白名单放在转发器里判断: 非白名单的 CONNECT 直接 TCP 隧道,
//      不经 Rust 代理 MITM, 避免污染其它 App 的 WebView。
//   5) NSURLSessionConfiguration hook 只在 WebKit 进程生效,
//      不再拖死 App 自身的 URLSession。
//
// 前提: FluxDo 的代理对 CONNECT 做 TLS 解密(MITM), CA 必须已装进系统信任库。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <netdb.h>
#import <arpa/inet.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <sys/select.h>
#import <pthread.h>
#import <fcntl.h>
#import <errno.h>
#import <unistd.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

#define WVP_DOMAIN      CFSTR("com.fluxdo.webviewproxy")
#define WVP_APP_BID     @"com.github.lingyan000.fluxdo"
#define WVP_WK_BID      @"com.apple.WebKit.Networking"
#define WVP_RELAY_PORT  65530
#define WVP_MAX_HEAD    8192
// 0.1.5: WebKit 网络进程的沙盒不允许写任何日志文件(fs_usage 实测: 注入后
// 该进程只有一次 stat64, 没有任何 open/write), 所以诊断只能靠网络信标:
// 每个被注入的进程在 loopback 上开一个只读 HTTP 端点, 用 SSH 探测即知
// 是否注入、构造函数是否执行、hook 被调用了几次。
//   App 进程      -> 65531
//   WebKit 网络进程 -> 65532
//   其它进程       -> 65533
#define WVP_BEACON_APP    65531
#define WVP_BEACON_WKNET  65532
#define WVP_BEACON_OTHER  65533
#define WVP_BEACON_SLOTS  4

static volatile int gProxyCalls  = 0;  // CFNetworkCopySystemProxySettings 被调用次数
static volatile int gProxyHit    = 0;  // 其中成功返回代理的次数
static volatile int gProxyMiss   = 0;  // 其中判定不该接管(转发器不在/禁用)的次数

extern CFDictionaryRef CFNetworkCopySystemProxySettings(void);

#pragma mark - 日志

static NSString *WVPWriteLine(NSString *path, NSString *line) {
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [path stringByDeletingLastPathComponent];
    if (![fm fileExistsAtPath:dir])
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    if (![fm fileExistsAtPath:path])
        [fm createFileAtPath:path contents:nil attributes:nil];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) return nil;
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
    NSLog(@"[WebViewProxy] %@", msg);

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

#pragma mark - 配置

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
    if (p > 0 && p < 65536) return p;
    return [WVPGet(@"DetectedPort") intValue];
}

static BOOL WVPGlobalMode(void) {
    NSString *mode = WVPGet(@"Mode");
    return [mode isEqualToString:@"global"];
}

static NSArray<NSString *> *WVPDomains(void) {
    id d = WVPGet(@"Domains");
    if ([d isKindOfClass:[NSArray class]] && [(NSArray *)d count]) return (NSArray *)d;
    return @[@"linux.do"];
}

static BOOL WVPShouldProxyHost(NSString *host) {
    if (WVPGlobalMode()) return YES;
    if (!host.length) return NO;
    NSString *h = [host lowercaseString];
    for (NSString *d in WVPDomains()) {
        NSString *dl = [[d description] lowercaseString];
        if (!dl.length) continue;
        if ([h isEqualToString:dl]) return YES;
        if ([h hasSuffix:[@"." stringByAppendingString:dl]]) return YES;
    }
    return NO;
}

#pragma mark - socket 工具

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

// 带超时的 TCP 连接, 成功返回 fd, 失败 -1
static int WVPConnectHost(NSString *host, int port, int timeoutMs) {
    if (!host.length || port <= 0 || port > 65535) return -1;
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo *res = NULL;
    if (getaddrinfo([host UTF8String], portstr, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, 0);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r == 0) { fcntl(fd, F_SETFL, flags); break; }
        if (errno == EINPROGRESS) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
            struct timeval tv; tv.tv_sec = timeoutMs / 1000; tv.tv_usec = (timeoutMs % 1000) * 1000;
            if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
                int err = 0; socklen_t len = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) { fcntl(fd, F_SETFL, flags); break; }
            }
        }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void WVPPump(int from, int to) {
    char buf[16384];
    for (;;) {
        ssize_t n = recv(from, buf, sizeof(buf), 0);
        if (n <= 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = send(to, buf + off, (size_t)(n - off), 0);
            if (w <= 0) { shutdown(from, SHUT_RDWR); return; }
            off += w;
        }
    }
    shutdown(to, SHUT_WR);
}

typedef struct { int a; int b; } WVPPumpArgs;

static void *WVPPumpThread(void *arg) {
    WVPPumpArgs *p = (WVPPumpArgs *)arg;
    WVPPump(p->a, p->b);
    free(p);
    return NULL;
}

#pragma mark - 固定端口转发器 (App 进程内)

static void *WVPClientThread(void *arg) {
    int cfd = (int)(intptr_t)arg;

    struct timeval tv; tv.tv_sec = 3; tv.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char head[WVP_MAX_HEAD + 1];
    size_t hlen = 0;
    while (hlen < WVP_MAX_HEAD) {
        ssize_t n = recv(cfd, head + hlen, WVP_MAX_HEAD - hlen, 0);
        if (n <= 0) { close(cfd); return NULL; }
        hlen += (size_t)n;
        head[hlen] = 0;
        if (strstr(head, "\r\n\r\n")) break;
    }
    head[hlen] = 0;
    if (!hlen) { close(cfd); return NULL; }

    char method[16] = {0}, target[1024] = {0};
    if (sscanf(head, "%15s %1023s", method, target) != 2) { close(cfd); return NULL; }

    BOOL isConnect = (strcmp(method, "CONNECT") == 0);
    NSString *host = nil;
    int port = 0;

    if (isConnect) {
        NSString *hp = [NSString stringWithUTF8String:target];
        NSRange colon = [hp rangeOfString:@":" options:NSBackwardsSearch];
        if (colon.location != NSNotFound) {
            host = [hp substringToIndex:colon.location];
            port = [[hp substringFromIndex:colon.location + 1] intValue];
        } else {
            host = hp; port = 443;
        }
    } else {
        NSString *url = [NSString stringWithUTF8String:target];
        NSURL *u = [NSURL URLWithString:url];
        host = u.host;
        port = u.port ? [u.port intValue] : 80;
    }

    int upfd = -1;
    BOOL viaProxy = WVPShouldProxyHost(host);

    if (viaProxy) {
        int pport = WVPActivePort();
        if (pport > 0 && pport != WVP_RELAY_PORT) {
            upfd = WVPConnectHost(@"127.0.0.1", pport, 3000);
        }
    } else {
        upfd = WVPConnectHost(host, port, 5000);
        // 直连时由我们自己回 200 Connection Established
        if (upfd >= 0 && isConnect) {
            const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(cfd, ok, strlen(ok), 0);
        }
    }

    if (upfd < 0) {
        const char *err = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        send(cfd, err, strlen(err), 0);
        close(cfd);
        return NULL;
    }

    // 首包转发规则:
    //   CONNECT + 走代理 -> 把 CONNECT 头转给 Rust 代理, 由它回 200
    //   CONNECT + 直连   -> 上面已自行回 200, 头不能转
    //   非 CONNECT       -> 头就是要转发的请求本身
    BOOL forwardHead = isConnect ? viaProxy : YES;
    if (forwardHead && hlen) {
        ssize_t off = 0;
        while (off < (ssize_t)hlen) {
            ssize_t w = send(upfd, head + off, hlen - (size_t)off, 0);
            if (w <= 0) { close(cfd); close(upfd); return NULL; }
            off += w;
        }
    }

    struct timeval tv2; tv2.tv_sec = 0; tv2.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));
    setsockopt(upfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    setsockopt(upfd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));

    WVPPumpArgs *args = malloc(sizeof(WVPPumpArgs));
    args->a = upfd;
    args->b = cfd;
    pthread_t t;
    if (pthread_create(&t, NULL, WVPPumpThread, args) == 0) pthread_detach(t);
    else free(args);

    WVPPump(cfd, upfd);
    close(cfd);
    return NULL;
}

static void *WVPAcceptLoop(void *arg) {
    int lfd = (int)(intptr_t)arg;
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { usleep(20000); continue; }
        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        pthread_t t;
        if (pthread_create(&t, NULL, WVPClientThread, (void *)(intptr_t)cfd) == 0) pthread_detach(t);
        else close(cfd);
    }
    return NULL;
}

static void WVPStartRelay(void) {
    static BOOL started = NO;
    if (started) return;
    started = YES;

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { WVPLog(@"转发器 socket 创建失败: %d", errno); return; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(WVP_RELAY_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        WVPLog(@"转发器 bind %d 失败: %d (端口被占用?)", WVP_RELAY_PORT, errno);
        close(lfd);
        return;
    }
    if (listen(lfd, 128) != 0) {
        WVPLog(@"转发器 listen 失败: %d", errno);
        close(lfd);
        return;
    }
    pthread_t t;
    if (pthread_create(&t, NULL, WVPAcceptLoop, (void *)(intptr_t)lfd) == 0) {
        pthread_detach(t);
        WVPLog(@"转发器已监听 127.0.0.1:%d -> 代理端口(动态)", WVP_RELAY_PORT);
    } else {
        WVPLog(@"转发器线程创建失败");
        close(lfd);
    }
}

#pragma mark - 代理字典

static NSDictionary *WVPProxyDict(void) {
    static NSDictionary *cache = nil;
    static time_t lastCheck = 0;
    time_t now = time(NULL);
    if (cache && now - lastCheck < 2) return cache;
    lastCheck = now;
    cache = nil;

    if (!WVPEnabled()) return nil;
    // 转发器没起来(FluxDo 没运行)就交还原设置, 不碰别人的 WebView
    if (!WVPPortAlive(WVP_RELAY_PORT)) return nil;

    cache = @{
        @"HTTPEnable":  @YES,
        @"HTTPProxy":   @"127.0.0.1",
        @"HTTPPort":    @(WVP_RELAY_PORT),
        @"HTTPSEnable": @YES,
        @"HTTPSProxy":  @"127.0.0.1",
        @"HTTPSPort":   @(WVP_RELAY_PORT),
        @"ExceptionsList": @[@"127.0.0.1", @"localhost", @"::1"],
    };
    return cache;
}

#pragma mark - 进程识别

static BOOL gIsApp = NO;
static BOOL gIsWKNet = NO;

static BOOL WVPIsWebKitNet(void) {
    static BOOL computed = NO;
    if (computed) return gIsWKNet;
    computed = YES;
    NSString *name = [[NSProcessInfo processInfo] processName];
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    gIsWKNet = [name isEqualToString:WVP_WK_BID] || [bid isEqualToString:WVP_WK_BID];
    return gIsWKNet;
}

#pragma mark - 网络信标 (0.1.5 诊断用)

static void *WVPBeaconClient(void *arg) {
    int cfd = (int)(intptr_t)arg;
    char req[512];
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    recv(cfd, req, sizeof(req) - 1, 0);

    char body[512];
    int blen = snprintf(body, sizeof(body),
        "pid=%d app=%d wknet=%d proxyCalls=%d hit=%d miss=%d relay=%d domains=%lu\n",
        getpid(), (int)gIsApp, (int)gIsWKNet,
        gProxyCalls, gProxyHit, gProxyMiss,
        WVP_RELAY_PORT, (unsigned long)WVPDomains().count);

    char head[256];
    int hlen = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
        "Connection: close\r\n\r\n", blen);
    if (hlen > 0) send(cfd, head, (size_t)hlen, 0);
    if (blen > 0) send(cfd, body, (size_t)blen, 0);
    close(cfd);
    return NULL;
}

static void *WVPBeaconAccept(void *arg) {
    int lfd = (int)(intptr_t)arg;
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { usleep(50000); continue; }
        pthread_t t;
        if (pthread_create(&t, NULL, WVPBeaconClient, (void *)(intptr_t)cfd) == 0) pthread_detach(t);
        else close(cfd);
    }
    return NULL;
}

static void WVPStartBeacon(int port) {
    static int used[WVP_BEACON_SLOTS];
    static int n = 0;
    for (int i = 0; i < n; i++) if (used[i] == port) return;
    if (n < WVP_BEACON_SLOTS) used[n++] = port;

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return;
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(lfd); return; }
    if (listen(lfd, 16) != 0) { close(lfd); return; }
    pthread_t t;
    if (pthread_create(&t, NULL, WVPBeaconAccept, (void *)(intptr_t)lfd) == 0) pthread_detach(t);
    else close(lfd);
}

#pragma mark - Hooks

// 系统代理设置: iOS 上 CFNetwork 读取系统代理的唯一入口
// (SCDynamicStoreCopyProxies 在 iOS SDK 里被标记为 unavailable, 不能用)
%hookf(CFDictionaryRef, CFNetworkCopySystemProxySettings) {
    if (WVPIsWebKitNet()) {
        gProxyCalls++;
        NSDictionary *p = WVPProxyDict();
        if (p) {
            gProxyHit++;
            static time_t lastLog = 0;
            time_t now = time(NULL);
            if (now - lastLog > 10) { lastLog = now; WVPLog(@"CFNetwork 取代理 -> %d", WVP_RELAY_PORT); }
            return (CFDictionaryRef)CFBridgingRetain(p);
        }
        gProxyMiss++;
    }
    return %orig;
}

// FluxDo 进程: 本地代理 listen() 时抓到端口
%hookf(int, listen, int sockfd, int backlog) {
    int r = %orig;
    if (r == 0 && gIsApp) {
        struct sockaddr_in a; socklen_t len = sizeof(a);
        memset(&a, 0, sizeof(a));
        if (getsockname(sockfd, (struct sockaddr *)&a, &len) == 0 && a.sin_family == AF_INET) {
            int port = ntohs(a.sin_port);
            BOOL loopback = (ntohl(a.sin_addr.s_addr) == INADDR_LOOPBACK);
            if (loopback && port > 1024 && port < 65535 &&
                port != 8181 && port != 50300 && port != 50301 && port != WVP_RELAY_PORT) {
                if ([WVPGet(@"DetectedPort") intValue] != port) {
                    WVPut(@"DetectedPort", @(port));
                    WVPLog(@"捕获本地监听端口 %d", port);
                }
            }
        }
    }
    return r;
}

// 只在 WebKit 网络进程里接管 NSURLSessionConfiguration (App 自身不受影响)
%hook NSURLSessionConfiguration

- (NSDictionary *)connectionProxyDictionary {
    if (WVPIsWebKitNet()) {
        NSDictionary *p = WVPProxyDict();
        if (p) return p;
    }
    return %orig;
}

+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
    NSURLSessionConfiguration *c = %orig();
    if (WVPIsWebKitNet()) {
        NSDictionary *p = WVPProxyDict();
        if (p) c.connectionProxyDictionary = p;
    }
    return c;
}

+ (NSURLSessionConfiguration *)ephemeralSessionConfiguration {
    NSURLSessionConfiguration *c = %orig();
    if (WVPIsWebKitNet()) {
        NSDictionary *p = WVPProxyDict();
        if (p) c.connectionProxyDictionary = p;
    }
    return c;
}

%end

%hook WKWebView
- (instancetype)initWithFrame:(CGRect)frame configuration:(WKWebViewConfiguration *)configuration {
    if (gIsApp) {
        WVPLog(@"新建 WebView, 代理端口 %d, 转发器端口 %d", WVPActivePort(), WVP_RELAY_PORT);
    }
    return %orig;
}
%end

%ctor {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    NSString *pname = [[NSProcessInfo processInfo] processName];
    BOOL isApp = [bid isEqualToString:WVP_APP_BID] || [pname isEqualToString:WVP_APP_BID];
    BOOL isNet = WVPIsWebKitNet();
    gIsApp = isApp;

    WVPLog(@"=== 0.1.5 loaded into %@ (pid %d, app=%d, wknet=%d) ===",
           bid ?: @"?", getpid(), isApp, isNet);

    // 信标先起, 哪怕后面全部失败也能被 SSH 看到
    WVPStartBeacon(isApp ? WVP_BEACON_APP : (isNet ? WVP_BEACON_WKNET : WVP_BEACON_OTHER));

    if (isApp) {
        WVPStartRelay();
        WVPLog(@"App 进程就绪, 等待 listen()");
    } else if (isNet) {
        WVPLog(@"网络进程就绪, 代理 -> 127.0.0.1:%d, 白名单=%@",
               WVP_RELAY_PORT, WVPDomains());
    }
}
