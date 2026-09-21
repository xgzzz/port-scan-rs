//! 网卡扫描与网卡抓包引擎。
//!
//! - 启用 `pcap` 特性：接口列表来自 libpcap / Npcap，抓包为真实网卡抓包，支持 BPF 过滤；
//! - 未启用：接口列表退化为操作系统查询（Windows PowerShell / Linux sysfs），抓包不可用。

use crate::table::render_table;
use anyhow::Result;
use colored::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

/// 是否编译进了真实网卡抓包能力
pub const PCAP_ENABLED: bool = cfg!(feature = "pcap");

/// 运行期检测 `wpcap.dll` 能否加载（即 Npcap / WinPcap 是否已安装）。
///
/// 构建时 `wpcap.dll` 是延迟加载的，所以没装 Npcap 的机器也能正常启动，
/// 这里返回 `false` 时给出安装引导即可，不会让进程崩溃。
///
/// 注意：新版 Npcap 会把 DLL 放在 `%SystemRoot%\System32\Npcap\`，该目录**不在**
/// DLL 搜索路径里，只按名字加载会找不到，因此再按已知路径逐个尝试
/// （加载成功后模块以基名注册，延迟加载即可命中，无需改 PATH）。
#[cfg(feature = "pcap")]
pub fn pcap_runtime_ready() -> bool {
    #[cfg(target_os = "windows")]
    {
        // 1) 标准搜索路径：exe 同目录 / System32 / PATH（WinPcap 兼容模式就是这种）
        if try_load_dll("wpcap.dll") {
            return true;
        }

        // 2) Npcap 1.8x 的默认安装位置
        let system_root =
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let mut candidates = vec![
            format!("{}\\System32\\Npcap\\wpcap.dll", system_root),
            format!("{}\\SysWOW64\\Npcap\\wpcap.dll", system_root),
        ];
        if let Ok(program_files) = std::env::var("ProgramFiles") {
            candidates.push(format!("{}\\Npcap\\wpcap.dll", program_files));
        }

        candidates.iter().any(|path| try_load_dll(path.as_str()))
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

/// 试加载一个 DLL；刻意不释放，让它常驻以便后面的延迟加载直接命中
#[cfg(all(feature = "pcap", target_os = "windows"))]
fn try_load_dll(name: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::LoadLibraryW;

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())).is_ok() }
}

/// Npcap 不可用时的统一引导文案
#[cfg(feature = "pcap")]
fn npcap_missing_error() -> anyhow::Error {
    anyhow::anyhow!(
        "未检测到 Npcap（无法加载 wpcap.dll），网卡抓包暂不可用。\n\
         请先安装 Npcap: https://npcap.com/#download\n\
         安装时勾选 \"Install Npcap in WinPcap API-compatible Mode\"，装完重启本程序。\n\
         注意: 端口扫描（local / scan）与 pcap 分析（analyze）不需要 Npcap，可正常使用。"
    )
}

/// 一块网卡的信息
#[derive(Clone, Debug, serde::Serialize)]
pub struct IfaceInfo {
    /// 抓包时传给 `--interface` 的名称
    pub name: String,
    /// 接口描述，取不到时为空串
    pub description: String,
    /// MAC 地址（尽力获取）
    pub mac: Option<String>,
    /// 已配置的地址，形如 `192.168.1.10/24`
    pub addresses: Vec<String>,
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub wireless: bool,
}

impl IfaceInfo {
    /// 状态文本，如 `UP,RUNNING`
    pub fn status_text(&self) -> String {
        let mut parts = Vec::new();
        if self.up {
            parts.push("UP");
        }
        if self.running {
            parts.push("RUNNING");
        }
        if self.loopback {
            parts.push("LOOPBACK");
        }
        if self.wireless {
            parts.push("WIRELESS");
        }
        if parts.is_empty() {
            "DOWN".to_string()
        } else {
            parts.join(",")
        }
    }

    /// 下拉列表里的简短标签
    pub fn label(&self) -> String {
        let desc = if self.description.trim().is_empty() {
            String::new()
        } else {
            format!(" - {}", self.description)
        };
        let addr = self
            .addresses
            .first()
            .map(|a| format!(" [{}]", a))
            .unwrap_or_default();
        format!("{}{}{}", self.name, desc, addr)
    }
}

/// 实时抓包预览行
#[derive(Clone, Debug)]
pub struct PreviewRow {
    pub seq: u64,
    pub timestamp: f64,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: u32,
    pub summary: String,
}

/// 抓包线程回传的事件
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum IfaceEvent {
    Status(String),
    Packet(PreviewRow),
}

/// 抓包计数（跨线程读取）
#[derive(Default)]
pub struct CaptureCounters {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
}

/// 抓包句柄：用于请求停止与读取统计
#[derive(Clone)]
pub struct IfaceCaptureHandle {
    stop: Arc<AtomicBool>,
    counters: Arc<CaptureCounters>,
}

impl IfaceCaptureHandle {
    /// 请求停止抓包（线程会在下一个读取超时周期退出）
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// 返回 (已抓包数, 已抓字节数)
    pub fn counters(&self) -> (u64, u64) {
        (
            self.counters.packets.load(Ordering::Relaxed),
            self.counters.bytes.load(Ordering::Relaxed),
        )
    }
}

/// 时间戳格式化为本地时间 `HH:MM:SS.mmm`
pub fn format_time(ts: f64) -> String {
    let secs = ts as i64;
    let millis = ((ts - secs as f64) * 1000.0).round().clamp(0.0, 999.0) as u32;
    chrono::DateTime::from_timestamp(secs, millis * 1_000_000)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S%.3f")
                .to_string()
        })
        .unwrap_or_else(|| format!("{:.3}", ts))
}

/// 单行预览文本（CLI `--preview` 使用）
#[allow(dead_code)]
pub fn format_preview(row: &PreviewRow) -> String {
    format!(
        "#{:<6} {} {:<24} -> {:<24} {:<14} {:>6} B  {}",
        row.seq,
        format_time(row.timestamp),
        row.src,
        row.dst,
        row.protocol,
        row.length,
        row.summary
    )
}

// ---------------------------------------------------------------------------
// 接口枚举
// ---------------------------------------------------------------------------

/// 列出本机可抓包的网卡
#[cfg(feature = "pcap")]
pub fn list_interfaces() -> Result<Vec<IfaceInfo>> {
    if !pcap_runtime_ready() {
        return Err(npcap_missing_error());
    }

    let macs = os_interface_macs();
    let mut out = Vec::new();
    for dev in pcap::Device::list()? {
        out.push(IfaceInfo {
            // Windows 下设备名形如 \Device\NPF_{GUID}，按 GUID 去系统信息里取 MAC
            mac: macs
                .get(&guid_key(&dev.name))
                .cloned()
                .or_else(|| macs.get(&dev.name).cloned()),
            name: dev.name.clone(),
            description: dev.desc.clone().unwrap_or_default(),
            addresses: dev.addresses.iter().map(format_address).collect(),
            up: dev.flags.is_up(),
            running: dev.flags.is_running(),
            loopback: dev.flags.is_loopback(),
            wireless: dev.flags.is_wireless(),
        });
    }
    sort_ifaces(&mut out);
    Ok(out)
}

/// 列出本机网卡（未启用 pcap 特性，无法直接抓包）
#[cfg(not(feature = "pcap"))]
pub fn list_interfaces() -> Result<Vec<IfaceInfo>> {
    #[cfg(target_os = "windows")]
    let out = list_interfaces_powershell();
    #[cfg(not(target_os = "windows"))]
    let out = list_interfaces_sysfs();
    out
}

#[allow(dead_code)]
fn sort_ifaces(ifaces: &mut [IfaceInfo]) {
    ifaces.sort_by(|a, b| {
        b.running
            .cmp(&a.running)
            .then_with(|| a.loopback.cmp(&b.loopback))
            .then_with(|| a.name.cmp(&b.name))
    });
}

#[cfg(feature = "pcap")]
fn format_address(a: &pcap::Address) -> String {
    match a.netmask {
        Some(mask) => format!("{}/{}", a.addr, prefix_len(mask)),
        None => a.addr.to_string(),
    }
}

#[cfg(feature = "pcap")]
fn prefix_len(mask: std::net::IpAddr) -> u8 {
    match mask {
        std::net::IpAddr::V4(v4) => u32::from(v4).count_ones() as u8,
        std::net::IpAddr::V6(v6) => v6.octets().iter().map(|b| b.count_ones() as u8).sum(),
    }
}

/// 通过 PowerShell 枚举网卡（未启用 pcap 特性时的退化实现）
#[allow(dead_code)]
fn list_interfaces_powershell() -> Result<Vec<IfaceInfo>> {
    // 适配器信息与 IP 信息分成两类行输出，回到 Rust 再按 ifIndex 合并，
    // 避免在 PowerShell 里维护哈希表。
    let script = r#"
Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object {
    "IP|{0}|{1}/{2}" -f $_.InterfaceIndex, $_.IPAddress, $_.PrefixLength
}
Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
    "AD|{0}|{1}|{2}|{3}|{4}" -f $_.ifIndex, $_.Name, $_.InterfaceDescription, $_.MacAddress, $_.Status
}
"#;
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map_err(|e| anyhow::anyhow!("调用 PowerShell 失败: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let mut adapters: Vec<(u32, IfaceInfo)> = Vec::new();
    let mut ips: HashMap<u32, Vec<String>> = HashMap::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        match parts.as_slice() {
            ["IP", index, addr, ..] => {
                if let Ok(i) = index.trim().parse::<u32>() {
                    ips.entry(i).or_default().push(addr.trim().to_string());
                }
            }
            ["AD", index, name, desc, mac, status, ..] => {
                let desc = desc.trim().to_string();
                let mac = mac.trim().replace('-', ":").to_uppercase();
                let status = status.trim();
                let lower = desc.to_lowercase();
                adapters.push((
                    index.trim().parse::<u32>().unwrap_or(0),
                    IfaceInfo {
                        name: name.trim().to_string(),
                        description: desc,
                        mac: if mac.matches(':').count() == 5 {
                            Some(mac)
                        } else {
                            None
                        },
                        addresses: Vec::new(),
                        up: status.eq_ignore_ascii_case("up"),
                        running: status.eq_ignore_ascii_case("up"),
                        loopback: lower.contains("loopback"),
                        wireless: lower.contains("wireless")
                            || lower.contains("wi-fi")
                            || lower.contains("wlan")
                            || lower.contains("802.11"),
                    },
                ));
            }
            _ => {}
        }
    }

    let mut out = Vec::with_capacity(adapters.len());
    for (index, mut info) in adapters {
        info.addresses = ips.remove(&index).unwrap_or_default();
        out.push(info);
    }
    sort_ifaces(&mut out);
    Ok(out)
}

/// 通过 `/sys/class/net` 枚举网卡（非 Windows 平台的退化实现）
#[allow(dead_code)]
fn list_interfaces_sysfs() -> Result<Vec<IfaceInfo>> {
    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|e| anyhow::anyhow!("读取 /sys/class/net 失败: {}", e))?;

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let base = format!("/sys/class/net/{}", name);
        let read = |field: &str| {
            std::fs::read_to_string(format!("{}/{}", base, field))
                .map(|s| s.trim().to_string())
                .ok()
        };

        let mac = read("address")
            .filter(|m| !m.is_empty())
            .map(|m| m.to_uppercase());
        let operstate = read("operstate").unwrap_or_default();
        let iflags = read("flags")
            .map(|f| u32::from_str_radix(f.trim_start_matches("0x"), 16).unwrap_or(0))
            .unwrap_or(0);

        out.push(IfaceInfo {
            name,
            description: String::new(),
            mac,
            addresses: Vec::new(),
            up: operstate == "up" || operstate == "unknown",
            running: operstate == "up",
            // IFF_LOOPBACK
            loopback: iflags & 0x8 != 0,
            wireless: std::path::Path::new(&format!("{}/wireless", base)).exists(),
        });
    }
    sort_ifaces(&mut out);
    Ok(out)
}

// ---------------------------------------------------------------------------
// MAC 地址（尽力而为地补齐 pcap 不提供的链路层地址）
// ---------------------------------------------------------------------------

/// 取出设备名里的 `{GUID}` 片段，用于与系统网卡信息对齐
#[allow(dead_code)]
fn guid_key(name: &str) -> String {
    match (name.find('{'), name.rfind('}')) {
        (Some(a), Some(b)) if b > a => name[a..=b].to_uppercase(),
        _ => name.to_uppercase(),
    }
}

/// 从 PowerShell 读取 `网卡GUID -> MAC`
#[allow(dead_code)]
fn macs_from_powershell() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let script = r#"
Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
    "{0}|{1}" -f $_.InterfaceGuid, $_.MacAddress
}
"#;
    let output = match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
    {
        Ok(o) => o,
        Err(_) => return map,
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut it = line.trim().split('|');
        if let (Some(guid), Some(mac)) = (it.next(), it.next()) {
            let guid = guid.trim().to_uppercase();
            let mac = mac.trim().replace('-', ":").to_uppercase();
            if !guid.is_empty() && mac.matches(':').count() == 5 {
                map.insert(guid, mac);
            }
        }
    }
    map
}

/// 从 `/sys/class/net/*/address` 读取 `网卡名 -> MAC`
#[allow(dead_code)]
fn macs_from_sysfs() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(mac) = std::fs::read_to_string(format!("/sys/class/net/{}/address", name)) {
                let mac = mac.trim().to_uppercase();
                if !mac.is_empty() {
                    map.insert(name, mac);
                }
            }
        }
    }
    map
}

#[allow(dead_code)]
fn os_interface_macs() -> HashMap<String, String> {
    #[cfg(target_os = "windows")]
    let map = macs_from_powershell();
    #[cfg(not(target_os = "windows"))]
    let map = macs_from_sysfs();
    map
}

// ---------------------------------------------------------------------------
// 抓包引擎
// ---------------------------------------------------------------------------

/// 启动网卡抓包。
///
/// - `interface`：`list_interfaces()` 返回的 `name`
/// - `filter`：BPF 过滤表达式（如 `tcp port 80`），空串表示不过滤
/// - `save_path`：可选的 pcap 落盘路径
/// - `tx`：预览事件回传通道
///
/// 打开设备、编译 BPF 等错误会同步返回；开始抓包后出错则通过 `IfaceEvent::Status` 通知。
#[cfg(feature = "pcap")]
pub fn start_capture(
    interface: &str,
    filter: Option<String>,
    save_path: Option<std::path::PathBuf>,
    tx: mpsc::Sender<IfaceEvent>,
) -> Result<IfaceCaptureHandle> {
    use pcap::{Capture, Device};

    if !pcap_runtime_ready() {
        return Err(npcap_missing_error());
    }

    let mut cap = Capture::from_device(Device::from(interface))
        .map_err(|e| anyhow::anyhow!("打开网卡 {} 失败: {}", interface, e))?
        .snaplen(65535)
        .promisc(true)
        // 立即模式：包一到就交给应用，预览更实时
        .immediate_mode(true)
        .timeout(200)
        .open()
        .map_err(|e| {
            anyhow::anyhow!(
                "启动抓包失败: {}（Windows 需安装 Npcap，并建议以管理员身份运行）",
                e
            )
        })?;

    if let Some(expr) = filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        cap.filter(expr, true)
            .map_err(|e| anyhow::anyhow!("BPF 过滤表达式 `{}` 无效: {}", expr, e))?;
    }

    let linktype = cap.get_datalink();
    let link_kind = crate::parser::LinkKind::from_linktype(linktype.0);
    let link_name = linktype
        .get_name()
        .unwrap_or_else(|_| format!("linktype-{}", linktype.0));

    let mut savefile = match &save_path {
        Some(path) => Some(
            cap.savefile(path)
                .map_err(|e| anyhow::anyhow!("创建抓包文件失败: {}", e))?,
        ),
        None => None,
    };

    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(CaptureCounters::default());
    let handle = IfaceCaptureHandle {
        stop: Arc::clone(&stop),
        counters: Arc::clone(&counters),
    };

    let _ = tx.send(IfaceEvent::Status(format!(
        "开始抓包: {} ({})",
        interface, link_name
    )));

    let thread_stop = Arc::clone(&stop);
    let thread_counters = Arc::clone(&counters);
    std::thread::spawn(move || {
        let mut seq = 0u64;
        loop {
            if thread_stop.load(Ordering::SeqCst) {
                break;
            }
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(sf) = savefile.as_mut() {
                        sf.write(&packet);
                    }

                    let ts =
                        packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1e6;
                    thread_counters.packets.fetch_add(1, Ordering::Relaxed);
                    thread_counters
                        .bytes
                        .fetch_add(packet.data.len() as u64, Ordering::Relaxed);
                    seq += 1;

                    let parsed =
                        crate::parser::parse_link_frame(packet.data, seq, ts, link_kind);
                    let row = PreviewRow {
                        seq,
                        timestamp: ts,
                        src: format_addr(parsed.src_ip.as_deref(), parsed.src_port),
                        dst: format_addr(parsed.dst_ip.as_deref(), parsed.dst_port),
                        protocol: protocol_label(&parsed),
                        length: packet.data.len() as u32,
                        summary: crate::parser::packet_summary(&parsed, packet.data),
                    };

                    if tx.send(IfaceEvent::Packet(row)).is_err() {
                        break; // 接收端已经关闭
                    }
                }
                // 读取超时：没有新包，继续下一轮（顺便检查停止标志）
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => break,
                Err(e) => {
                    let _ = tx.send(IfaceEvent::Status(format!("抓包出错: {}", e)));
                    break;
                }
            }
        }

        if let Some(sf) = savefile.as_mut() {
            let _ = sf.flush();
        }
        let _ = tx.send(IfaceEvent::Status("已停止抓包".to_string()));
    });

    Ok(handle)
}

/// 未启用 `pcap` 特性时的占位实现
#[cfg(not(feature = "pcap"))]
pub fn start_capture(
    _interface: &str,
    _filter: Option<String>,
    _save_path: Option<std::path::PathBuf>,
    _tx: mpsc::Sender<IfaceEvent>,
) -> Result<IfaceCaptureHandle> {
    Err(anyhow::anyhow!(
        "当前编译未启用 pcap 特性，无法抓取网卡流量；重新编译: cargo build --release --features pcap"
    ))
}

#[cfg(feature = "pcap")]
fn format_addr(ip: Option<&str>, port: Option<u16>) -> String {
    match (ip, port) {
        (Some(ip), Some(port)) => format!("{}:{}", ip, port),
        (Some(ip), None) => ip.to_string(),
        _ => "-".to_string(),
    }
}

#[cfg(feature = "pcap")]
fn protocol_label(p: &crate::parser::ParsedPacket) -> String {
    match &p.tcp_flags {
        Some(flags) => format!("TCP [{}]", flags),
        None => p.protocol.clone(),
    }
}

// ---------------------------------------------------------------------------
// CLI 输出
// ---------------------------------------------------------------------------

/// 打印网卡列表（CLI `ifaces` 子命令）
pub fn print_interfaces(json: bool) -> Result<()> {
    let ifaces = list_interfaces()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&ifaces)?);
        return Ok(());
    }

    if ifaces.is_empty() {
        println!("{}", "(未发现可用网卡)".yellow());
        return Ok(());
    }

    let header = vec![
        "#".to_string(),
        "网卡名".to_string(),
        "描述".to_string(),
        "地址".to_string(),
        "MAC".to_string(),
        "状态".to_string(),
    ];
    let rows: Vec<Vec<String>> = ifaces
        .iter()
        .enumerate()
        .map(|(i, f)| {
            vec![
                (i + 1).to_string(),
                f.name.clone(),
                dash_if_empty(&f.description),
                if f.addresses.is_empty() {
                    "-".to_string()
                } else {
                    f.addresses.join(", ")
                },
                f.mac.clone().unwrap_or_else(|| "-".to_string()),
                f.status_text(),
            ]
        })
        .collect();

    println!("\n=== 本机网卡 ({} 个) ===", ifaces.len());
    println!("{}", render_table(&header, &rows));

    if PCAP_ENABLED {
        println!(
            "指定网卡抓包: port-scan-rs {} --interface <网卡名>",
            "capture".cyan()
        );
    } else {
        println!(
            "{}",
            "提示: 当前未启用 pcap 特性，只能查看网卡信息，无法抓包。".yellow()
        );
        println!(
            "{}",
            "      启用方式: cargo build --release --features pcap".yellow()
        );
    }
    Ok(())
}

fn dash_if_empty(s: &str) -> String {
    if s.trim().is_empty() {
        "-".to_string()
    } else {
        s.to_string()
    }
}
