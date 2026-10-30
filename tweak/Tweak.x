// WebViewProxy 0.1.12 - 让 FluxDo 的 WKWebView 走它自己的本地 DoH 代理
//
// 0.1.12 (关键修复): 加进程归属判定
//   com.apple.WebKit.Networking 是所有 App 共用的系统网络进程族。
//   0.1.11 只按进程名判断, 于是给设备上每一个 WebView 都塞了
//   HTTPProxy=127.0.0.1:65530。FluxDo 一旦被 iOS 挂起, 65530 变成
//   「能连但不回话」的黑洞, 其它 App 的网页全部卡死 —— 即
//   「开着 VPN 用过一次 FluxDo, 整机断网」。
//   现在用 responsibility 私有 API 问内核「我是替谁干活」,
//   只有责任进程是 FluxDo 时才接管。
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
#import <CFNetwork/CFProxySupport.h>
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
#import <dlfcn.h>
#import <sys/sysctl.h>

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
// 0.1.10: 日志上限保护。日志是纯诊断用途, 只追加不轮转会无限增长。
// 超过 256KB 时裁掉旧内容, 只保留最近 128KB(从整行边界开始),
// 并在文件头写一行说明。写入只发生在 App 进程, 频率极低(实测 5 小时 8KB)。
#define WVP_LOG_MAX_BYTES  (256 * 1024)
#define WVP_LOG_KEEP_BYTES (128 * 1024)

static volatile int gProxyCalls  = 0;  // CFNetworkCopySystemProxySettings 被调用次数
static volatile int gProxyHit    = 0;  // 其中成功返回代理的次数
static volatile int gProxyMiss   = 0;  // 其中判定不该接管(转发器不在/禁用)的次数
static volatile int gCallsForURL  = 0;  // CFNetworkCopyProxiesForURL 调用次数
static volatile int gHitForURL    = 0;  // 其中我们返回了代理
static volatile int gCallsAutoCfg = 0;  // CFNetworkCopyProxiesForAutoConfigurationScript
// 0.1.9: 关键怀疑 —— wknet 走 NSURLSessionConfiguration.connectionProxyDictionary,
// 根本不经过 CFNetworkCopy* 三个函数, 所以那三个计数永远是 0。
// 这里给 NSURLSessionConfiguration 三个方法加计数, 再 hook connect() 直接数
// "本进程有没有连过 127.0.0.1:65530", 一次就能定性。
static volatile int gNsCfgGet      = 0;  // -connectionProxyDictionary 被读次数
static volatile int gNsCfgDefault  = 0;  // +defaultSessionConfiguration 被调次数
static volatile int gNsCfgEphemeral= 0;  // +ephemeralSessionConfiguration 被调次数
static volatile int gConnRelay     = 0;  // connect() 到 127.0.0.1:65530 的次数
static volatile int gConnTotal     = 0;  // connect() 总次数(本进程)
// 0.1.11: 信标跟随 FluxDo 生命周期。
// com.apple.WebKit.Networking 是系统常驻进程, 注入后信标会一直监听,
// 即使 FluxDo 已经退出。这里用看门狗盯住转发器 65530:
// 每秒探测一次, 连续 3 次不通(约 3 秒)就关掉信标; 转发器回来后自动重开。
#define WVP_BEACON_DEAD_TRIES 3
static int gBeaconFd = -1;              // 当前监听中的信标 fd, -1 表示未监听
static volatile int gRelayConns  = 0;  // 转发器 accept 到的连接总数
static volatile int gPumpUp      = 0;  // 客户端 -> 上游 的字节数
static volatile int gPumpDown    = 0;  // 上游 -> 客户端 的字节数
#ifndef SOL_LOCAL
#define SOL_LOCAL 0
#endif
#ifndef LOCAL_PEERPID
#define LOCAL_PEERPID 0x002
#endif

static volatile int gLastPeerPid  = 0;  // 最近一条连到转发器的连接来自哪个 pid
static volatile int gPeerPidPrev  = 0;  // 上一条
static volatile int gPeerPidPrev2 = 0;  // 上上条
static volatile int gLastHostLen = 0;  // 最近一次请求头的长度(粗略显示有无流量)
static char         gLastReq[128] = {0}; // 最近一次请求的首行(CONNECT 目标/路径)

extern CFDictionaryRef CFNetworkCopySystemProxySettings(void);
extern CFArrayRef CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef proxySettings);
extern CFArrayRef CFNetworkCopyProxiesForAutoConfigurationScript(CFStringRef script, CFURLRef targetURL, CFErrorRef *error);

#pragma mark - 日志

// 文件超过上限就裁到最近 WVP_LOG_KEEP_BYTES, 从下一个换行开始, 不留半行。
static void WVPRotateIfNeeded(NSString *path) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attr = [fm attributesOfItemAtPath:path error:nil];
    if (!attr) return;
    unsigned long long sz = [[attr objectForKey:NSFileSize] unsignedLongLongValue];
    if (sz <= WVP_LOG_MAX_BYTES) return;

    NSData *old = [NSData dataWithContentsOfFile:path];
    if (!old) return;
    if (old.length <= WVP_LOG_KEEP_BYTES) {
        [fm createFileAtPath:path contents:nil attributes:nil];
        return;
    }
    NSData *tail = [old subdataWithRange:NSMakeRange(old.length - WVP_LOG_KEEP_BYTES, WVP_LOG_KEEP_BYTES)];
    const char *p = (const char *)tail.bytes;
    NSUInteger off = 0;
    while (off < tail.length && p[off] != '\n') off++;
    if (off < tail.length) off++;

    NSMutableData *nd = [NSMutableData data];
    NSString *hdr = [NSString stringWithFormat:
        @"[%@] [pid %d] 日志超过 %dKB, 已裁掉旧内容, 保留最近 %dKB\n",
        [NSDate date], getpid(), (int)(WVP_LOG_MAX_BYTES / 1024), (int)(WVP_LOG_KEEP_BYTES / 1024)];
    [nd appendData:[hdr dataUsingEncoding:NSUTF8StringEncoding]];
    if (off < tail.length) [nd appendData:[tail subdataWithRange:NSMakeRange(off, tail.length - off)]];
    [nd writeToFile:path atomically:YES];
}

static NSString *WVPWriteLine(NSString *path, NSString *line) {
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = [path stringByDeletingLastPathComponent];
    if (![fm fileExistsAtPath:dir])
        [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    if (![fm fileExistsAtPath:path])
        [fm createFileAtPath:path contents:nil attributes:nil];
    WVPRotateIfNeeded(path);
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

static void WVPPumpDir(int from, int to, int dir) {
    char buf[16384];
    for (;;) {
        ssize_t n = recv(from, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (dir > 0) gPumpUp += (int)n; else gPumpDown += (int)n;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = send(to, buf + off, (size_t)(n - off), 0);
            if (w <= 0) { shutdown(from, SHUT_RDWR); return; }
            off += w;
        }
    }
    shutdown(to, SHUT_WR);
}

static void WVPPump(int from, int to) { WVPPumpDir(from, to, 0); }

typedef struct { int a; int b; int dir; } WVPPumpArgs;

static void *WVPPumpThread(void *arg) {
    WVPPumpArgs *p = (WVPPumpArgs *)arg;
    WVPPumpDir(p->a, p->b, p->dir);
    free(p);
    return NULL;
}

#pragma mark - 固定端口转发器 (App 进程内)

static void *WVPClientThread(void *arg) {
    int cfd = (int)(intptr_t)arg;

    {
        int peer = 0; socklen_t plen = sizeof(peer);
        if (getsockopt(cfd, SOL_LOCAL, LOCAL_PEERPID, &peer, &plen) == 0 && peer > 0) {
            gPeerPidPrev2 = gPeerPidPrev;
            gPeerPidPrev  = gLastPeerPid;
            gLastPeerPid  = peer;
        }
    }

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

    gLastHostLen = (int)hlen;
    snprintf(gLastReq, sizeof(gLastReq), "%s %s", method, target);

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
    args->dir = -1;
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
        gRelayConns++;
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

#pragma mark - 代理数组 (CFNetworkCopyProxiesForURL 返回值)

// CFNetworkCopyProxiesForURL 要的是「代理数组」, 每个元素是一个字典:
//   kCFProxyTypeKey  = kCFProxyTypeHTTP / kCFProxyTypeHTTPS
//   kCFProxyHostNameKey / kCFProxyPortNumberKey
// 与系统代理设置用的是完全不同的键, 不能复用 WVPProxyDict。
// 另外必须保留一个 kCFProxyTypeNone 兜底项, 否则 CFNetwork 认为无可用代理。
static CFArrayRef WVPProxyArray(void) {
    if (!WVPEnabled()) return NULL;
    if (!WVPPortAlive(WVP_RELAY_PORT)) return NULL;

    CFStringRef host = CFSTR("127.0.0.1");
    int port = WVP_RELAY_PORT;

    CFMutableArrayRef arr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if (!arr) return NULL;

    const void *types[2] = { kCFProxyTypeHTTP, kCFProxyTypeHTTPS };
    for (int i = 0; i < 2; i++) {
        CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (!d) continue;
        CFNumberRef pn = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &port);
        CFDictionarySetValue(d, kCFProxyTypeKey, types[i]);
        CFDictionarySetValue(d, kCFProxyHostNameKey, host);
        CFDictionarySetValue(d, kCFProxyPortNumberKey, pn);
        if (pn) CFRelease(pn);
        CFArrayAppendValue(arr, d);
        CFRelease(d);
    }
    return arr;
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

#pragma mark - 进程归属判定 (0.1.12)

// 用 responsibility 私有 API 问内核 "我是替哪个进程干活"。
// com.apple.WebKit.Networking 是系统共享的, 光看进程名无法区分 Safari 与 FluxDo。
static volatile int  gRespPid     = 0;    // 责任进程 pid, 0=还没查到
static volatile int  gEligible    = -1;   // -1 未判定, 0 不接管, 1 接管
static volatile int  gRespFnFound = 0;    // responsibility 符号是否存在
static volatile int  gPathSrc     = 0;    // 路径来源: 1=proc_pidpath 2=sysctl 0=失败
static volatile int  gRespTries   = 0;    // 查了几次
static char          gRespPath[256] = {0};

typedef pid_t (*WVPRespFn)(pid_t);
typedef int   (*WVPProcPathFn)(int, char *, unsigned int);

static void WVPGetProcPath(int pid, char *out, size_t outlen) {
    if (!out || outlen < 2) return;
    out[0] = 0;
    static WVPProcPathFn pf = NULL;
    static BOOL looked = NO;
    if (!looked) {
        looked = YES;
        void *lh = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY);
        if (lh) pf = (WVPProcPathFn)dlsym(lh, "proc_pidpath");
        if (!pf) pf = (WVPProcPathFn)dlsym(RTLD_DEFAULT, "proc_pidpath");
    }
    if (pf && pf(pid, out, (unsigned int)outlen) > 0 && out[0]) {
        gPathSrc = 1;
        return;
    }
    // 兜底: sysctl KERN_PROCARGS2, 结构是 [int argc][可执行路径\0]...
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t size = 4096;
    char *buf = (char *)malloc(size);
    if (!buf) return;
    if (sysctl(mib, 3, buf, &size, NULL, 0) == 0 && size > sizeof(int)) {
        const char *p = buf + sizeof(int);
        const char *end = buf + size;
        const char *q = p;
        while (q < end && *q) q++;
        size_t n = (size_t)(q - p);
        if (n > 0 && n < outlen) {
            memcpy(out, p, n);
            out[n] = 0;
            gPathSrc = 2;
        }
    }
    free(buf);
}

static void WVPResolveResponsible(void) {
    if (gRespPid > 0) return;
    static WVPRespFn rfn = NULL;
    static BOOL looked = NO;
    if (!looked) {
        looked = YES;
        rfn = (WVPRespFn)dlsym(RTLD_DEFAULT, "responsibility_get_pid_responsible_for_pid");
        if (!rfn) {
            const char *libs[] = { "/usr/lib/libsystem_kernel.dylib",
                                   "/usr/lib/libSystem.B.dylib",
                                   "/usr/lib/libdispatch.dylib",
                                   NULL };
            for (int i = 0; libs[i] && !rfn; i++) {
                void *h = dlopen(libs[i], RTLD_LAZY);
                if (!h) continue;
                rfn = (WVPRespFn)dlsym(h, "responsibility_get_pid_responsible_for_pid");
            }
        }
    }
    gRespFnFound = rfn ? 1 : 0;
    if (!rfn) return;
    pid_t p = rfn(getpid());
    if (p <= 0) return;
    gRespPid = (int)p;
    WVPGetProcPath((int)p, gRespPath, sizeof(gRespPath) - 1);
}

static BOOL WVPPathIsFluxDo(const char *path) {
    if (!path || !path[0]) return NO;
    char low[256];
    size_t n = strlen(path);
    if (n >= sizeof(low)) n = sizeof(low) - 1;
    for (size_t i = 0; i < n; i++) {
        char c = path[i];
        low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    low[n] = 0;
    return strstr(low, "/runner.app/") != NULL;
}

static BOOL WVPIsProxyEligible(void) {
    if (!WVPIsWebKitNet()) return NO;
    if (gEligible >= 0) return gEligible == 1;
    gRespTries++;
    WVPResolveResponsible();
    if (gRespPid <= 0) {
        // 查不到: 前 20 次继续重试(可能进程刚起), 之后永久放弃, 安全优先
        if (gRespTries >= 20) gEligible = 0;
        return NO;
    }
    BOOL ok = WVPPathIsFluxDo(gRespPath);
    gEligible = ok ? 1 : 0;
    return ok;
}

#pragma mark - 网络信标 (0.1.5 诊断用)

static void *WVPBeaconClient(void *arg) {
    int cfd = (int)(intptr_t)arg;
    char req[512];
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    recv(cfd, req, sizeof(req) - 1, 0);

    char body[1024];
    int blen = snprintf(body, sizeof(body),
        "ver=0.1.12 pid=%d app=%d wknet=%d\n"
        "sysCalls=%d sysHit=%d sysMiss=%d\n"
        "forURLCalls=%d forURLHit=%d autoCfgCalls=%d\n"
        "relayPort=%d relayConns=%d up=%d down=%d\n"
        "activePort=%d domains=%lu global=%d enabled=%d\n"
        "lastHeadLen=%d lastReq=[%s]\n"
        "peerPid=%d peerPrev=%d peerPrev2=%d\n"
        "nsCfgGet=%d nsCfgDef=%d nsCfgEph=%d connRelay=%d connTotal=%d\n"
        "respPid=%d eligible=%d respFn=%d tries=%d pathSrc=%d respPath=[%s]\n",
        getpid(), (int)gIsApp, (int)gIsWKNet,
        gProxyCalls, gProxyHit, gProxyMiss,
        gCallsForURL, gHitForURL, gCallsAutoCfg,
        WVP_RELAY_PORT, gRelayConns, gPumpUp, gPumpDown,
        WVPActivePort(), (unsigned long)WVPDomains().count,
        (int)WVPGlobalMode(), (int)WVPEnabled(),
        gLastHostLen, gLastReq,
        gLastPeerPid, gPeerPidPrev, gPeerPidPrev2,
        gNsCfgGet, gNsCfgDefault, gNsCfgEphemeral, gConnRelay, gConnTotal,
        gRespPid, gEligible, gRespFnFound, gRespTries, gPathSrc, gRespPath);

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
    (void)arg;
    for (;;) {
        int lfd = gBeaconFd;
        if (lfd < 0) break;                 // 看门狗已关闭, 线程退出
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (gBeaconFd < 0) break;       // 关闭导致的失败, 退出
            usleep(50000);
            continue;
        }
        pthread_t t;
        if (pthread_create(&t, NULL, WVPBeaconClient, (void *)(intptr_t)cfd) == 0) pthread_detach(t);
        else close(cfd);
    }
    return NULL;
}

static BOOL WVPStartBeacon(int port) {
    if (gBeaconFd >= 0) return YES;         // 已经在监听

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return NO;
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(lfd); return NO; }
    if (listen(lfd, 16) != 0) { close(lfd); return NO; }
    gBeaconFd = lfd;
    pthread_t t;
    if (pthread_create(&t, NULL, WVPBeaconAccept, NULL) == 0) pthread_detach(t);
    else { gBeaconFd = -1; close(lfd); return NO; }
    return YES;
}

// 关掉信标监听; accept 线程会自己退出。
static void WVPStopBeacon(void) {
    int fd = gBeaconFd;
    gBeaconFd = -1;
    if (fd >= 0) close(fd);
}

// 看门狗: 每秒探测转发器, 连续 WVP_BEACON_DEAD_TRIES 次不通就关信标,
// 恢复后自动重开。只在 WebKit 网络进程里跑(App 进程的信标随 App 存亡, 不需要)。
static void *WVPBeaconWatchdog(void *arg) {
    int port = (int)(intptr_t)arg;
    int dead = 0;
    BOOL logState = NO;
    for (;;) {
        sleep(1);
        BOOL alive = WVPPortAlive(WVP_RELAY_PORT);
        if (alive) {
            dead = 0;
            if (gBeaconFd < 0) {
                if (WVPStartBeacon(port) && !logState) {
                    WVPLog(@"信标恢复监听 %d (转发器已就绪)", port);
                    logState = YES;
                }
            }
        } else {
            if (gBeaconFd >= 0 && ++dead >= WVP_BEACON_DEAD_TRIES) {
                WVPStopBeacon();
                logState = NO;
            }
        }
    }
    return NULL;
}

static void WVPStartBeaconWatchdog(int port) {
    pthread_t t;
    if (pthread_create(&t, NULL, WVPBeaconWatchdog, (void *)(intptr_t)port) == 0) pthread_detach(t);
}

#pragma mark - Hooks

// 系统代理设置: iOS 上 CFNetwork 读取系统代理的唯一入口
// (SCDynamicStoreCopyProxies 在 iOS SDK 里被标记为 unavailable, 不能用)
%hookf(CFDictionaryRef, CFNetworkCopySystemProxySettings) {
    if (WVPIsProxyEligible()) {
        gProxyCalls++;
        NSDictionary *p = WVPProxyDict();
        if (p) { gProxyHit++; return (CFDictionaryRef)CFBridgingRetain(p); }
        gProxyMiss++;
    }
    return %orig;
}

// WebKit 真正的入口: CFNetwork 在发请求前用这个函数把「URL -> 代理列表」算出来。
// 只要在这里返回我们的转发器, WKWebView 的所有请求就会走 127.0.0.1:65530。
%hookf(CFArrayRef, CFNetworkCopyProxiesForURL, CFURLRef url, CFDictionaryRef proxySettings) {
    if (WVPIsProxyEligible()) {
        gCallsForURL++;
        NSString *host = nil;
        if (url) {
            CFStringRef h = CFURLCopyHostName(url);
            if (h) { host = (__bridge_transfer NSString *)h; }
        }
        if (host && !WVPShouldProxyHost(host)) return %orig;
        CFArrayRef arr = WVPProxyArray();
        if (arr) { gHitForURL++; return arr; }
    }
    return %orig;
}

// PAC 脚本路径: 仅计数, 不改行为。
%hookf(CFArrayRef, CFNetworkCopyProxiesForAutoConfigurationScript, CFStringRef script, CFURLRef targetURL, CFErrorRef *error) {
    if (WVPIsProxyEligible()) gCallsAutoCfg++;
    return %orig;
}

// 0.1.9: 直接数 connect()。本进程只要连过 127.0.0.1:65530,
// 就证明是它把流量送进了转发器 —— 无论经过哪个 API。
%hookf(int, connect, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
        gConnTotal++;
        if (ntohs(a4->sin_port) == WVP_RELAY_PORT &&
            ntohl(a4->sin_addr.s_addr) == INADDR_LOOPBACK) {
            gConnRelay++;
        }
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
    if (WVPIsProxyEligible()) {
        gNsCfgGet++;
        NSDictionary *p = WVPProxyDict();
        if (p) return p;
    }
    return %orig;
}

+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
    NSURLSessionConfiguration *c = %orig();
    if (WVPIsProxyEligible()) {
        gNsCfgDefault++;
        NSDictionary *p = WVPProxyDict();
        if (p) c.connectionProxyDictionary = p;
    }
    return c;
}

+ (NSURLSessionConfiguration *)ephemeralSessionConfiguration {
    NSURLSessionConfiguration *c = %orig();
    if (WVPIsProxyEligible()) {
        gNsCfgEphemeral++;
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

    WVPLog(@"=== 0.1.12 loaded into %@ (pid %d, app=%d, wknet=%d) ===",
           bid ?: @"?", getpid(), isApp, isNet);

    // 信标先起, 哪怕后面全部失败也能被 SSH 看到
    // App 进程: 信标随 App 存亡, 不需要看门狗
    // 网络进程: 系统常驻, 必须由看门狗跟住转发器
    int bport = isApp ? WVP_BEACON_APP : (isNet ? WVP_BEACON_WKNET : WVP_BEACON_OTHER);
    WVPStartBeacon(bport);
    if (!isApp) WVPStartBeaconWatchdog(bport);

    if (isApp) {
        WVPStartRelay();
        WVPLog(@"App 进程就绪, 等待 listen()");
    } else if (isNet) {
        WVPLog(@"网络进程就绪, 代理 -> 127.0.0.1:%d, 白名单=%@",
               WVP_RELAY_PORT, WVPDomains());
    }
}
