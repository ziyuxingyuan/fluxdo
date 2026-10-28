# FluxDo WebView Proxy

一个 Dopamine (rootless) 越狱插件, 让 FluxDo 的 **WKWebView 走 FluxDo 自己的本地 DoH 代理**, 从而在 iOS 16 上不用再开全局代理。

## 它解决什么

FluxDo 用 Rust (doh_proxy) 在 `127.0.0.1` 起一个 HTTP CONNECT 代理, App 自己的 Dart 请求已经走它。
但 WKWebView 的请求发在独立进程 `com.apple.WebKit.Networking` 里, 拿不到这份配置, 于是网页流量仍然走系统 DNS —— 被污染就登录不了。

插件做两件事:

1. 在 FluxDo 进程里枚举自己的 LISTEN socket, 找到代理端口, 写进 CFPreferences 域 `com.fluxdo.webviewproxy` 的 `DetectedPort`。
2. 在 WebKit 网络进程里 hook `NSURLSessionConfiguration` 和 `SCDynamicStoreCopyProxies`, 强制返回这个代理。

## 前提条件 (缺一不可)

1. **必须先把 FluxDo 的 CA 证书装进系统信任库。**
   FluxDo 的代理对 CONNECT 做 TLS 解密 (MITM), 不装 CA 的话所有 HTTPS 页面会直接报证书错误。
   - 在 FluxDo 里导出 CA (设置里的代理/证书相关项), 存成 `ca.pem`
   - rootless 越狱下执行:
     ```
     security add-trusted-cert -d -r trustRoot -k /private/var/Keychains/System.keychain /path/to/ca.pem
     ```
2. **FluxDo 里必须开启 DoH 代理并保持运行**, 本地端口不存在时插件不会生效。
3. 越狱为 **Dopamine (rootless)**, iOS 15.0 - 16.6.1。

## 编译

### 方式 A: 有 macOS / WSL + Theos

```bash
export THEOS=~/theos
make clean package THEOS_PACKAGE_SCHEME=rootless
```
产物在 `packages/com.fluxdo.webviewproxy_0.1.0_iphoneos-arm64.deb`。

### 方式 B: 没有开发环境 (Windows)

用 GitHub Actions 的 macOS runner 编译, 见仓库里的 `.github/workflows/build-tweak.yml`。

## 安装

```bash
# 拷到设备
scp packages/*.deb root@<设备IP>:/var/mobile/
# 设备上
ssh root@<设备IP>
dpkg -i /var/mobile/com.fluxdo.webviewproxy_0.1.0_iphoneos-arm64.deb
killall -9 Runner
killall -9 com.apple.WebKit.Networking
```

或者直接用 Sileo / Zebra 安装 deb。

## 配置

配置存在 CFPreferences 域 `com.fluxdo.webviewproxy`, 对应文件 `/var/mobile/Library/Preferences/com.fluxdo.webviewproxy.plist`。

| 键 | 类型 | 说明 |
|---|---|---|
| `Enabled` | bool | 总开关, 缺省 true |
| `Host` | string | 代理地址, 缺省 `127.0.0.1` |
| `Port` | int | 手动指定端口; 填了就不自动探测 |
| `DetectedPort` | int | 插件自动写入的探测结果, 不要手改 |
| `Mode` | string | `pac`(默认) 只让 Domains 里的域名走代理; `global` 全部 WebView 流量都走代理 |
| `Domains` | array | PAC 白名单, 缺省 `["linux.do"]`, 子域自动包含 |

### 两种模式的区别

- **pac (默认)**: 只有 `linux.do` 及其子域走 FluxDo 的代理, 其他站点的 WebView 请求照常直连。对别的 App 影响最小。
- **global**: 所有走 WebKit 的请求都进代理。隔离性差, 但兼容性最好 —— 如果 PAC 在你的系统上没生效, 用这个兜底。

### 安全阀

插件每次取配置前会先做一次本地 connect, 确认端口真的在监听。FluxDo 没开或代理没起来时直接返回"不接管", 不会把别的 App 的 WebView 打瘫。

改完执行 `killall -9 Runner` 让 FluxDo 重启。

## 排查

日志: `/var/mobile/Library/Logs/WebViewProxy.log`

正常情况应该看到:

```
loaded into com.github.lingyan000.fluxdo (pid 1234, app=1)
探测到本地代理端口 51234 并已写入配置域
loaded into com.apple.WebKit.Networking (pid 1300, app=0)
网络进程读到端口 51234
```

如果网络进程读到的是 `0`, 说明跨进程读配置被沙盒拦了, 这时在配置里手动填 `Port`。

## 影响范围 (重要)

WebKit 的网络进程 `com.apple.WebKit.Networking` 是**系统级共享**的, 不是 FluxDo 独占。所以插件必然会影响其他 App 的 WebView 请求。当前版本用两层把影响压到最小:

1. PAC 白名单 —— 只有 `Domains` 里的域名会进代理, 其他流量 DIRECT。
2. 端口存活检测 —— 代理没跑就直接不接管。

如果你要的是"完全只影响 FluxDo", 那得改成在 App 进程内设置 `WKWebsiteDataStore` 的私有代理属性 (隔离性好, 但 iOS 16 的私有接口需实测), 目前版本没有采用。

## 已知限制

- 只覆盖走 NSURLSession / CFNetwork 的 HTTP(S) 流量; WebSocket 如果走独立通道可能不受影响。
- 依赖 WebKit 内部实现, iOS 升级后可能要重新适配。
- MITM 会降低这一层的端到端加密强度, 但 FluxDo 本来就是这个设计。
- 插件不会修改 FluxDo 本体, 也不会动上游仓库。
