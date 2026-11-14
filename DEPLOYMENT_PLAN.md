# cfdata-trace 独立部署说明

## 部署范围

新建独立 Coolify 应用 `cfdata-trace`，域名为 `https://cfdata-trace.anglesya.win`，不修改或复用 `2btv.eu.org`、`h3probe.anglesya.win`、`tg.anglesya.win` 或其他现有服务。服务以 Trace 页面为首页，只注册登录、区域名单、任务状态/取消与导出所需路由；不开放原 CFData-WEB 的官方网段扫描界面，也不开放手工 IP 检测接口。

容器必须设置 `CFDATA_TRACE_ONLY=1`、`CFDATA_WEB_USER` 和 `CFDATA_WEB_PASSWORD`。没有用户名或密码时程序拒绝启动。登录 Cookie 带 `HttpOnly`、`SameSite=Lax` 和 `Secure`；对外只经 Coolify HTTPS 反向代理提供访问。容器以非 root 用户运行，不需要持久化卷；任务状态和结果存于进程内存，容器重启后清空。

## 候选源与探测行为

页面与服务端只允许 NiREvil/VLESS 公开区域名单作为候选源；省略 `source` 时也默认选择此来源，region-only 模式会拒绝 FOFA。部署不设置也不使用 `FOFA_KEY`。用户按 ISO 3166-1 alpha-2 地区选择候选，页面支持 JP/HK/SG/TW 和选择全部 249 个地区。名单运行时从上游动态下载；已审阅的本地快照为 3,920 条、覆盖 69 个地区，快照时间 2026-11-13 13:01 UTC；实时上游的记录数和覆盖范围可能变化。此名单只是粗筛数据，不等同于 FOFA 查询结果，也不证明支持任意目标域名。

服务对候选 IP 使用用户指定域名作为 TLS SNI 与 HTTP Host，执行完整证书链和主机名校验，固定请求 `GET /cdn-cgi/trace`。拒绝非公网地址及 CIDR/端口范围输入。Cloudflare 官方 IPv4/IPv6 清单仅下载用于排除命中地址，绝不作为候选扫描。默认每地区最多 10 条、整批最多 500 条、并发 8；硬上限分别为 100、2,000、16。结果可导出 TXT/CSV，供本地二次筛选。

## 运行与验证

根目录 `Dockerfile` 从 `combined_refactor/` 构建独立 Go 模块，产出无 CGO Linux 可执行文件，最终镜像为 Distroless 非 root。容器暴露 13335，Coolify 健康检查使用 `/healthz`。Trace-only 启动跳过原程序的测速源预检、Geo 初始化、更新检查和基础扫描页面/API。

本地通过 `go test ./...`、`go test -race ./...`、`go vet ./...`、Linux amd64 构建及页面 JavaScript 语法检查。运行冒烟验证通过登录/HTTPS Cookie 属性、首页跳转、249 项地区目录、空闲任务状态、安全取消、空 CSV 导出；FOFA API 来源被拒绝，手工探测接口不存在。部署检查不会启动任何候选任务，不连接任何候选 IP，也不执行全局扫描。
