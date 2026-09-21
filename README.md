# port-scan-rs

<img src="assets/icon/port-scan-rs-256.png" width="88" align="right" alt="port-scan-rs 图标">

![ci](https://github.com/xgzzz/port-scan-rs/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)

本地端口检测、抓包与抓包分析工具（CLI + GUI 双模式）。

## 安装

### Scoop（Windows）

```powershell
scoop bucket add xgzzz https://github.com/xgzzz/scoop-bucket
scoop install xgzzz/port-scan-rs
```

安装后会得到两个命令：

- `port-scan-rs` —— 零依赖版本，`local` / `scan` / `ifaces`(系统枚举) / `analyze` / `gui` 全部可用
- `port-scan-rs-full` —— 额外支持网卡抓包，需要自行安装 [Npcap](https://npcap.com/#download)（内核驱动无法打包分发；未安装时程序照常启动并给出安装提示）

同时会创建开始菜单与桌面快捷方式，指向包内的 `port-scan-rs-gui.exe`（GUI 专用程序，双击不会出现控制台黑窗口）。

### 直接下载

从 [Releases](https://github.com/xgzzz/port-scan-rs/releases) 下载 `port-scan-rs-<版本>-x64.zip`，解压即用。

## 功能

| 子命令 | 说明 |
|---|---|
| `local` | 扫描本机所有 TCP/UDP 端口（Windows 通过 PowerShell，Linux 通过 `/proc/net`）；Windows 下可显示占用进程与 PID |
| `scan` | 扫描远程主机端口，支持并发、超时、Banner 读取 |
| `ifaces` | 网卡扫描：列出本机网卡（名称/描述/IP/MAC/状态），支持 JSON 输出；Windows 回环网卡 `\Device\NPF_Loopback` 也在列表中，可用于抓本机回环流量 |
| `capture` | 网卡抓包：选定网卡 + BPF 过滤，支持实时预览（`--preview`）与落盘 pcap；未启用 pcap 特性时退化为回环监听 |
| `analyze` | 解析 pcap 文件：支持以太网 / NULL / RAW / LINUX_SLL 链路层，含 TCP/UDP 过滤、HTTP 识别、JSON 导出、协议统计、握手时间线、流导出 |
| `gui` | 启动 GUI 桌面版（Windows 原生窗口，无需外部依赖） |

## 构建

```bash
# 默认构建（CLI + GUI，无外部依赖）
cargo build --release

# 启用真实网卡抓包（ifaces 的 pcap 枚举 + capture 的网卡模式）
# Linux: sudo apt install libpcap-dev
cargo build --release --features pcap
```

Windows 上启用 `--features pcap` 还需要：

1. 安装 [Npcap](https://npcap.com/#download)，安装时勾选 **Install Npcap in WinPcap API-compatible Mode**（提供运行期的 `wpcap.dll`）；
2. 下载 **Npcap SDK** 压缩包并解压，例如 `C:\npcap-sdk`；
3. 构建前指定 SDK 的库目录，让链接器找到 `wpcap.lib`：

```powershell
$env:LIBPCAP_LIBDIR="C:\npcap-sdk\Lib\x64"
cargo build --release --features pcap
```

4. 如果构建成功但运行时进程立即退出、退出码为 `0xC0000135`（找不到 `wpcap.dll`），说明 Npcap 不是以 WinPcap 兼容模式安装的（DLL 在 `C:\Windows\System32\Npcap\` 且不在搜索路径里）。两种解决办法：

```powershell
# 办法一：把该目录加入用户 PATH
[Environment]::SetEnvironmentVariable(
  'Path',
  [Environment]::GetEnvironmentVariable('Path','User') + ';C:\Windows\System32\Npcap',
  'User')

# 办法二（仅本机开发用）：把 DLL 拷到 exe 同目录，应用目录的搜索优先级最高
Copy-Item 'C:\Windows\System32\Npcap\wpcap.dll','C:\Windows\System32\Npcap\Packet.dll' .\target\debug\ -Force
```

> 办法二只用于本机调试。发布时请让目标机器自行安装 Npcap（或勾选 WinPcap 兼容模式）。

### 关于分发（重要）

Npcap 由「内核驱动 `npcap.sys` + 用户态 `wpcap.dll` / `Packet.dll`」两部分组成：

- **驱动无法打包进 exe**，必须以管理员权限安装进系统，所以目标机器上无法做到「完全免安装」；用户态 DLL 虽可内置，但没有驱动同样抓不到包，意义不大。
- Npcap 免费版**禁止再分发**，把它内置进你的安装包属于再分发，需要购买 [Npcap OEM](https://npcap.com/oem/)（OEM 版提供可随产品分发的安装程序，这是厂商推荐的集成方式）。
- 本项目已把 `wpcap.dll` 改成**延迟加载**（见根目录 `build.rs`）：没装 Npcap 的机器上程序照常启动，`local` / `scan` / `analyze` 全部可用，只有 `ifaces` / `capture` 会给出安装引导，不会出现静默崩溃（退出码 `0xC0000135`）。
- 若你只需要「开箱即用、零依赖」，用默认构建（不带 `--features pcap`）发布即可，它完全不依赖 Npcap。

## 打包发布

一条命令同时产出两个产物：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-release.ps1
```

| 产物 | 构建特性 | 说明 |
|---|---|---|
| `dist/port-scan-rs-lite.exe` | 默认 | 零外部依赖，`local` / `scan` / `ifaces`(系统枚举) / `analyze` / `gui` 全部可用，无网卡抓包 |
| `dist/port-scan-rs-full.exe` | `pcap` | 额外支持网卡抓包；目标机器需自行安装 Npcap（未装时程序照常启动并给出安装引导） |
| `dist/port-scan-rs-gui.exe` | `pcap` | GUI 专用（Windows 子系统），双击**不会出现控制台黑窗口**；随 zip 一起分发 |

> 三个可执行文件由同一套代码编译：`port-scan-rs.exe` / `port-scan-rs-gui.exe` 是同一 package 的两个 bin 目标，区别只在于 PE 子系统（控制台 / GUI）。

脚本会自动在 `%NPCAP_SDK_DIR%\Lib\x64`、`%USERPROFILE%\npcap-sdk\Lib\x64`、`C:\npcap-sdk\Lib\x64`、`C:\Program Files\Npcap\SDK\Lib\x64` 中寻找 `wpcap.lib`，也可以显式指定：

```powershell
$env:LIBPCAP_LIBDIR = 'C:\npcap-sdk\Lib\x64'
```

其他选项：

- `-SkipFull`：手边没有 Npcap SDK 时只产出 lite
- `-Profile dev`：用 debug 配置快速验证打包流程
- `-OutDir <目录>`：自定义输出目录（默认 `dist`）

完成后会打印两个 exe 的大小与 SHA256 前 16 位。

> `scripts/build-release.ps1` 刻意只使用 ASCII 字符：Windows PowerShell 5.1 会把不带 BOM 的 `.ps1` 当作 ANSI 读取，脚本里出现中文会被打乱从而报语法错误。

## CLI 使用示例

### 1. 查看本机所有端口
```bash
port-scan-rs.exe local
```

### 2. 只看监听端口
```bash
port-scan-rs.exe local --listening
```

### 3. 按进程名过滤
```bash
port-scan-rs.exe local --listening --process chrome
```

### 4. 输出 JSON
```bash
port-scan-rs.exe local --listening --json > ports.json
```

### 5. 扫描远程主机
```bash
port-scan-rs.exe scan 127.0.0.1 --ports 80,443,3306,8080-8090
```

### 6. 高并发扫描 + 自定义超时
```bash
port-scan-rs.exe scan 192.168.1.1 --ports 1-10000 --concurrency 200 --timeout-ms 300
```

### 7. 查看本机网卡
```bash
port-scan-rs.exe ifaces
port-scan-rs.exe ifaces --json > ifaces.json
```

### 8. 网卡抓包（BPF 过滤 + 实时预览）
```bash
# 实时预览 100 个包，不落盘
port-scan-rs.exe capture --interface "\Device\NPF_{...}" --preview --count 100 --no-save

# 只抓 80 端口，写入 pcap 文件
port-scan-rs.exe capture --interface eth0 --filter "tcp port 80" --output http.pcap

# 抓够 500 个包或 1MB 后自动停止
port-scan-rs.exe capture --interface eth0 --filter "host 10.0.0.1 and udp" --count 500 --max-bytes 1048576
```

### 9. 解析 pcap 文件
```bash
port-scan-rs.exe analyze http.pcap
port-scan-rs.exe analyze http.pcap --tcp --limit 50
```

### 10. 协议统计 + 握手时间线 + 流导出
```bash
# 查看协议统计（TCP/UDP 分布、HTTP 请求数、标志位）
port-scan-rs.exe analyze http.pcap --stats

# 查看三次握手时间线
port-scan-rs.exe analyze http.pcap --handshakes

# 导出所有 TCP 流到目录
port-scan-rs.exe analyze http.pcap --export-streams ./streams/
```

## GUI 使用

```bash
port-scan-rs.exe gui
```

打开 GUI 后是「左侧导航 + 卡片式内容区」的布局，右上角可切换深色 / 浅色主题：

- **📊 抓包分析** — 打开 pcap 文件后展示统计磁贴（包数 / 字节 / TCP / UDP / HTTP / 握手 / 流数）、TCP 标志位分布（带占比条）、TCP 流 Top 8、三次握手时间线，以及可文本过滤、可选显示上限的包列表
- **🖥 本机端口** — 后台线程扫描本机端口，支持按端口 / 地址 / 进程名过滤、按协议筛选、只看 LISTEN
- **🌐 远程扫描** — 端口预设、并发与超时调节；结果表格展示端口 / 服务 / 状态 / Banner
- **📡 抓包** — 两种模式：
  - **网卡抓包**（需 `--features pcap`）：选择网卡（含描述 / MAC / IP / 状态徽章）、填写 BPF 过滤（带常用表达式快捷填充）、开始 / 停止抓包；实时预览源 / 目的地址、协议、字节数与摘要（HTTP 请求行、TCP 标志、载荷文本），支持显示过滤、自动滚动、清空，并可保存为 pcap 文件；
  - **回环监听**：本地监听 `127.0.0.1:8888`，实时解析 HTTP 请求/响应，适合调试本地 HTTP 客户端。

界面样式统一收敛在 `src/gui/theme.rs`：配色、间距、圆角以及卡片 / 徽章 / 按钮等组件都在那里，改一处即可全局换风格。

## 技术栈

- **Rust** — 核心语言
- **eframe / egui** — 原生 GUI（编译为单 .exe，无外部运行时）
- **clap 4** — 命令行解析
- **tokio** — 异步端口扫描
- **serde / serde_json** — JSON 导出
- **colored** — 终端彩色输出
- **pcap**（可选） — 网卡抓包

## 第三方资源

- GUI 中文字体：[文泉驿微米黑](https://github.com/anthonyfok/fonts-wqy-microhei)（Apache-2.0），内嵌于 exe，授权文本见 `assets/fonts/wqy-microhei.LICENSE.txt`
- 网卡抓包依赖 [Npcap](https://npcap.com/)（仅 `port-scan-rs-full` 需要，需用户自行安装，本项目不再分发其组件）

## 项目结构

```
port-scan-rs/
├── Cargo.toml
├── build.rs              # 嵌入 exe 图标；Windows + pcap 时把 wpcap.dll 改为延迟加载
├── .github/workflows/    # ci.yml（push/PR 编译校验）、release.yml（打 tag 自动发版）
├── assets/
│   ├── fonts/            # 内嵌中文字体（文泉驿微米黑）
│   └── icon/             # 应用图标（.ico/.rc，编译进 exe）
├── scripts/
│   ├── build-release.ps1 # 一键产出 lite / full 两个 exe，并打包 zip + sha256
│   └── make-icon.py      # 生成应用图标（需 Pillow，按尺寸分层渲染保证小图标清晰）
├── src/
│   ├── main.rs          # CLI 入口
│   ├── stats.rs         # 协议统计、TCP 流重组、握手时间线
│   ├── table.rs         # 表格渲染
│   ├── scanner/         # 端口扫描（local + remote）
│   ├── capture/         # 抓包
│   │   ├── mod.rs       # CLI 抓包入口（pcap / 回环 fallback）
│   │   └── netif.rs     # 网卡枚举 + 网卡抓包引擎（BPF 过滤 / 实时预览）
│   ├── parser/          # pcap 解析 + HTTP 识别 + 流导出
│   └── gui/             # GUI 桌面版（egui/eframe）
│       ├── mod.rs
│       ├── app.rs       # 左侧导航 + 四个页面
│       ├── theme.rs     # 配色 / 间距 / 可复用界面组件
│       └── capture_engine.rs  # 回环监听引擎
└── test.pcap            # 测试用 pcap
```
