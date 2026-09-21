use crate::table::render_table;
use anyhow::Result;
use colored::*;
use std::fs::File;
use std::io::Read;

/// 单个解析后的数据包
#[derive(Debug, Clone, serde::Serialize)]
pub struct ParsedPacket {
    pub seq: u64,
    pub timestamp: f64,
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: u16,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<String>,
    pub payload_size: usize,
    pub http: Option<HttpInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpInfo {
    pub method: String,
    pub path: String,
    pub version: String,
    pub status: Option<String>,
    pub body: String,
}

/// 链路层封装类型（只覆盖常见的几种，其余只保留长度信息）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkKind {
    /// DLT_EN10MB：以太网
    Ethernet,
    /// DLT_NULL(0) / DLT_LOOP(108)：4 字节地址族 + 原始 IP（Windows 回环网卡就是这个）
    Null,
    /// DLT_RAW：直接就是原始 IP
    Raw,
    /// DLT_LINUX_SLL：16 字节 cooked 头 + ethertype
    LinuxSll,
    /// 其它链路层（如 802.11、SLL2 等），不做协议解析
    Other,
}

impl LinkKind {
    /// 由 libpcap 的 linktype 数值映射
    pub fn from_linktype(value: i32) -> Self {
        match value {
            1 => LinkKind::Ethernet,
            0 | 108 => LinkKind::Null,
            12 | 101 => LinkKind::Raw,
            113 => LinkKind::LinuxSll,
            _ => LinkKind::Other,
        }
    }
}

/// 解析一帧链路层数据（供实时抓包复用）
#[allow(dead_code)]
pub fn parse_link_frame(data: &[u8], seq: u64, timestamp: f64, kind: LinkKind) -> ParsedPacket {
    match kind {
        LinkKind::Ethernet => parse_ethernet(data, seq, timestamp),
        LinkKind::Null => {
            let mut p = blank_frame(seq, timestamp, data.len(), "IP");
            if data.len() > 4 {
                let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let is_v4 = le == 2 || be == 2;
                let is_v6 = matches!(le, 23 | 24 | 28 | 30) || matches!(be, 23 | 24 | 28 | 30);
                let payload = &data[4..];
                p.protocol = if is_v4 {
                    parse_ipv4(payload, &mut p)
                } else if is_v6 {
                    parse_ipv6(payload, &mut p)
                } else {
                    // 地址族不识别的兜底：按 IP 版本号判断
                    parse_ip_auto(payload, &mut p)
                };
            }
            p
        }
        LinkKind::Raw => {
            let mut p = blank_frame(seq, timestamp, data.len(), "IP");
            p.protocol = parse_ip_auto(data, &mut p);
            p
        }
        LinkKind::LinuxSll => {
            let mut p = blank_frame(seq, timestamp, data.len(), "SLL");
            if data.len() > 16 {
                let ethertype = u16::from_be_bytes([data[14], data[15]]);
                p.ethertype = ethertype;
                let payload = &data[16..];
                p.protocol = match ethertype {
                    0x0800 => parse_ipv4(payload, &mut p),
                    0x86DD => parse_ipv6(payload, &mut p),
                    0x0806 => "ARP".into(),
                    other => format!("ethertype-0x{:04X}", other),
                };
            }
            p
        }
        LinkKind::Other => blank_frame(seq, timestamp, data.len(), "非以太网帧"),
    }
}

/// 空包骨架：只填序号/时间/长度与协议标签
fn blank_frame(seq: u64, timestamp: f64, len: usize, label: &str) -> ParsedPacket {
    ParsedPacket {
        seq,
        timestamp,
        src_mac: String::new(),
        dst_mac: String::new(),
        ethertype: 0,
        protocol: label.into(),
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        payload_size: len,
        http: None,
    }
}

/// 按 IP 首字节的版本号分派 IPv4 / IPv6
fn parse_ip_auto(payload: &[u8], p: &mut ParsedPacket) -> String {
    match payload.first().map(|b| b >> 4) {
        Some(4) => parse_ipv4(payload, p),
        Some(6) => parse_ipv6(payload, p),
        _ => "ip-unknown".into(),
    }
}

/// 抓包预览用的一行摘要
#[allow(dead_code)]
pub fn packet_summary(p: &ParsedPacket, raw: &[u8]) -> String {
    if let Some(h) = &p.http {
        if h.method == "RESPONSE" {
            return format!("HTTP 响应 {}", h.status.clone().unwrap_or_default());
        }
        return format!("HTTP {} {}", h.method, h.path);
    }

    let base = match p.protocol.as_str() {
        "TCP" => format!("TCP [{}]", p.tcp_flags.clone().unwrap_or_default()),
        other => other.to_string(),
    };

    if p.payload_size > 0 {
        // TCP/UDP 载荷正好是这一帧末尾的 payload_size 个字节
        let start = raw.len().saturating_sub(p.payload_size);
        let preview = text_preview(&raw[start..], 60);
        if preview.is_empty() {
            format!("{} | 载荷 {} B", base, p.payload_size)
        } else {
            format!("{} | {}", base, preview)
        }
    } else {
        base
    }
}

/// 从原始字节里提取一段单行可读文本
#[allow(dead_code)]
fn text_preview(bytes: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let filtered: String = text.chars().filter(|c| !c.is_control()).take(max).collect();
    filtered.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 解析 pcap 文件
pub fn parse_pcap(file: &str) -> Result<Vec<ParsedPacket>> {
    let mut f = File::open(file)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;

    // 由文件头魔数判定字节序与时间戳精度，不能一律按小端解析：
    // - D4 C3 B2 A1：小端写出（最常见），微秒
    // - A1 B2 C3 D4：大端写出，微秒
    // - 4D 3C B2 A1：小端写出，纳秒
    // - A1 B2 3C 4D：大端写出，纳秒
    let (little_endian, nanosecond) = match magic {
        [0xD4, 0xC3, 0xB2, 0xA1] => (true, false),
        [0xA1, 0xB2, 0xC3, 0xD4] => (false, false),
        [0x4D, 0x3C, 0xB2, 0xA1] => (true, true),
        [0xA1, 0xB2, 0x3C, 0x4D] => (false, true),
        [0x0A, 0x0D, 0x0D, 0x0A] => {
            return Err(anyhow::anyhow!(
                "{} 是 pcapng 格式，当前仅支持经典 pcap",
                file
            ))
        }
        _ => {
            return Err(anyhow::anyhow!(
                "不是有效的 pcap 文件（magic 不匹配: {:?}）",
                hex::encode(magic)
            ))
        }
    };
    let frac_divisor = if nanosecond { 1e9 } else { 1e6 };

    // 文件头剩余 20 字节：version(4) thiszone(4) sigfigs(4) snaplen(4) network(4)
    let mut buf = [0u8; 20];
    f.read_exact(&mut buf)?;
    let linktype = read_u32(&buf[16..20], little_endian) as i32;
    let link_kind = LinkKind::from_linktype(linktype);
    if link_kind == LinkKind::Other {
        return Err(anyhow::anyhow!(
            "暂不支持的链路层类型 linktype={}（支持 Ethernet=1 / NULL=0 / RAW=12 / LINUX_SLL=113）",
            linktype
        ));
    }

    let mut packets = Vec::new();
    let mut seq = 0u64;
    loop {
        let mut rh = [0u8; 16];
        match f.read_exact(&mut rh) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let ts_sec = read_u32(&rh[0..4], little_endian) as u64;
        let ts_usec = read_u32(&rh[4..8], little_endian);
        let caplen = read_u32(&rh[8..12], little_endian) as usize;

        if caplen == 0 {
            seq += 1;
            continue;
        }

        let mut data = vec![0u8; caplen];
        f.read_exact(&mut data)?;

        packets.push(parse_link_frame(
            &data,
            seq,
            ts_sec as f64 + ts_usec as f64 / frac_divisor,
            link_kind,
        ));
        seq += 1;
    }
    Ok(packets)
}

/// 按指定字节序读取 4 字节无符号整数
fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

fn parse_ethernet(data: &[u8], seq: u64, ts: f64) -> ParsedPacket {
    let mut packet = ParsedPacket {
        seq,
        timestamp: ts,
        src_mac: String::new(),
        dst_mac: String::new(),
        ethertype: 0,
        protocol: "unknown".into(),
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
        payload_size: 0,
        http: None,
    };

    if data.len() < 14 {
        return packet;
    }
    packet.dst_mac = mac_str(&data[0..6]);
    packet.src_mac = mac_str(&data[6..12]);
    packet.ethertype = u16::from_be_bytes([data[12], data[13]]);

    let payload = &data[14..];
    match packet.ethertype {
        0x0800 => {
            packet.protocol = parse_ipv4(payload, &mut packet);
        }
        0x86DD => {
            packet.protocol = parse_ipv6(payload, &mut packet);
        }
        0x0806 => packet.protocol = "ARP".into(),
        0x8100 => {
            if payload.len() >= 16 {
                let inner_ethertype = u16::from_be_bytes([payload[12], payload[13]]);
                let inner_payload = &payload[16..];
                packet.ethertype = inner_ethertype;
                match inner_ethertype {
                    0x0800 => {
                        packet.protocol = parse_ipv4(inner_payload, &mut packet);
                    }
                    0x86DD => {
                        packet.protocol = parse_ipv6(inner_payload, &mut packet);
                    }
                    _ => packet.protocol = "vlan-unknown".into(),
                }
            }
        }
        _ => packet.protocol = format!("ethertype-0x{:04X}", packet.ethertype),
    }
    packet
}

fn parse_ipv4(payload: &[u8], p: &mut ParsedPacket) -> String {
    if payload.len() < 20 {
        return "ipv4-incomplete".into();
    }
    let ihl = (payload[0] & 0x0F) as usize * 4;
    let protocol = payload[9];
    let src_ip = format!(
        "{}.{}.{}.{}",
        payload[12], payload[13], payload[14], payload[15]
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        payload[16], payload[17], payload[18], payload[19]
    );
    p.src_ip = Some(src_ip);
    p.dst_ip = Some(dst_ip);

    let inner = if ihl > 0 && ihl <= payload.len() {
        &payload[ihl..]
    } else {
        &[]
    };
    match protocol {
        6 => parse_tcp(inner, p),
        17 => parse_udp(inner, p),
        _ => "ipv4-other".into(),
    }
}

fn parse_ipv6(payload: &[u8], p: &mut ParsedPacket) -> String {
    if payload.len() < 40 {
        return "ipv6-incomplete".into();
    }
    let nh = payload[6];
    let src_ip = ipv6_str(&payload[8..24]);
    let dst_ip = ipv6_str(&payload[24..40]);
    p.src_ip = Some(src_ip);
    p.dst_ip = Some(dst_ip);
    let inner = &payload[40..];
    match nh {
        6 => parse_tcp(inner, p),
        17 => parse_udp(inner, p),
        _ => "ipv6-other".into(),
    }
}

fn parse_tcp(inner: &[u8], p: &mut ParsedPacket) -> String {
    if inner.len() < 20 {
        return "tcp-short".into();
    }
    let sport = u16::from_be_bytes([inner[0], inner[1]]);
    let dport = u16::from_be_bytes([inner[2], inner[3]]);
    p.src_port = Some(sport);
    p.dst_port = Some(dport);

    let data_offset = ((inner[12] >> 4) & 0x0F) as usize * 4;
    let flags = inner[13];
    p.tcp_flags = Some(format_tcp_flags(flags));
    if data_offset > 0 && data_offset <= inner.len() {
        p.payload_size = inner.len() - data_offset;
        let payload = &inner[data_offset..];
        p.http = try_parse_http(payload);
    }
    "TCP".into()
}

fn parse_udp(inner: &[u8], p: &mut ParsedPacket) -> String {
    if inner.len() < 8 {
        return "udp-short".into();
    }
    let sport = u16::from_be_bytes([inner[0], inner[1]]);
    let dport = u16::from_be_bytes([inner[2], inner[3]]);
    p.src_port = Some(sport);
    p.dst_port = Some(dport);
    p.payload_size = inner.len() - 8;
    let payload = &inner[8..];
    p.http = try_parse_http(payload);
    "UDP".into()
}

fn format_tcp_flags(flags: u8) -> String {
    let mut s = String::new();
    if flags & 0x01 != 0 {
        s.push_str("FIN,");
    }
    if flags & 0x02 != 0 {
        s.push_str("SYN,");
    }
    if flags & 0x04 != 0 {
        s.push_str("RST,");
    }
    if flags & 0x08 != 0 {
        s.push_str("PSH,");
    }
    if flags & 0x10 != 0 {
        s.push_str("ACK,");
    }
    if flags & 0x20 != 0 {
        s.push_str("URG,");
    }
    if s.ends_with(',') {
        s.pop();
    }
    if s.is_empty() {
        "NONE".into()
    } else {
        s
    }
}

fn mac_str(b: &[u8]) -> String {
    (0..6)
        .map(|i| format!("{:02X}", b[i]))
        .collect::<Vec<_>>()
        .join(":")
}

fn ipv6_str(b: &[u8]) -> String {
    use std::net::Ipv6Addr;
    let mut arr = [0u8; 16];
    arr.copy_from_slice(b);
    Ipv6Addr::from(arr).to_string()
}

fn try_parse_http(payload: &[u8]) -> Option<HttpInfo> {
    let text = String::from_utf8_lossy(payload);
    // 跳过 TCP 段末尾可能存在的 NULL 字节 padding
    let trimmed = text.trim_start_matches('\0');
    parse_http_payload(trimmed)
}

/// 从文本中解析 HTTP 请求/响应（公开供 GUI 复用）
pub fn parse_http_payload(text: &str) -> Option<HttpInfo> {
    let trimmed = text.trim_start_matches('\0');
    if let Some(line) = trimmed.lines().next() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            let method = parts[0].to_string();
            let path = parts[1].to_string();
            let version = parts[2].to_string();
            if method != "HTTP/1.1" && method != "HTTP/1.0" {
                return Some(HttpInfo {
                    method,
                    path,
                    version,
                    status: None,
                    body: trimmed.to_string(),
                });
            }
        }
        if line.starts_with("HTTP/") {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                return Some(HttpInfo {
                    method: "RESPONSE".into(),
                    path: String::new(),
                    version: parts[0].to_string(),
                    status: Some(parts[1].to_string()),
                    body: trimmed.to_string(),
                });
            }
        }
    }
    None
}

/// 分析入口
pub fn analyze(
    file: &str,
    tcp_only: bool,
    udp_only: bool,
    http_only: bool,
    http_json: bool,
    limit: Option<usize>,
) -> Result<()> {
    let packets = parse_pcap(file)?;
    let total = packets.len();

    let filtered: Vec<&ParsedPacket> = packets
        .iter()
        .filter(|p| {
            if tcp_only && !p.protocol.starts_with("TCP") {
                return false;
            }
            if udp_only && !p.protocol.starts_with("UDP") {
                return false;
            }
            if http_only && p.http.is_none() {
                return false;
            }
            true
        })
        .take(limit.unwrap_or(usize::MAX))
        .collect();

    if http_json {
        let http_pkts: Vec<&ParsedPacket> =
            packets.iter().filter(|p| p.http.is_some()).collect();
        let json = serde_json::to_string_pretty(&http_pkts)?;
        println!("{}", json);
        return Ok(());
    }

    println!(
        "\n=== 解析 {} : 共 {} 包，显示 {} 包 ===",
        file.cyan(),
        total,
        filtered.len()
    );

    let header = vec![
        "#".to_string(),
        "时间".to_string(),
        "源 IP".to_string(),
        "目的 IP".to_string(),
        "源端口".to_string(),
        "目的端口".to_string(),
        "协议".to_string(),
        "载荷".to_string(),
        "HTTP".to_string(),
    ];
    let rows: Vec<Vec<String>> = filtered
        .iter()
        .map(|p| {
            let proto = if p.tcp_flags.is_some() {
                format!(
                    "{} [{}]",
                    p.protocol,
                    p.tcp_flags.clone().unwrap_or_default()
                )
            } else {
                p.protocol.clone()
            };
            let http = p
                .http
                .as_ref()
                .map(|h| format!("{} {}", h.method, h.path))
                .unwrap_or_else(|| "-".into());
            vec![
                p.seq.to_string(),
                format!("{:.4}", p.timestamp),
                p.src_ip.clone().unwrap_or_else(|| "-".into()),
                p.dst_ip.clone().unwrap_or_else(|| "-".into()),
                p.src_port
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "-".into()),
                p.dst_port
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "-".into()),
                proto,
                p.payload_size.to_string(),
                http,
            ]
        })
        .collect();

    println!("{}", render_table(&header, &rows));
    Ok(())
}

/// 统计并展示协议层 + TCP 标志位分布
pub fn print_protocol_stats(file: &str) -> Result<()> {
    let packets = parse_pcap(file)?;
    let stats = crate::stats::compute_stats(&packets);
    println!(
        "\n=== 协议统计: {} ({} 包, {} 字节, {} 流) ===",
        file.cyan(),
        stats.total_packets,
        stats.total_bytes,
        stats.flow_count
    );

    let rows: Vec<Vec<String>> = vec![
        vec![
            "TCP".into(),
            stats.tcp_packets.to_string(),
            format!("{:.1}%", stats.tcp_pct()),
        ],
        vec![
            "UDP".into(),
            stats.udp_packets.to_string(),
            format!("{:.1}%", stats.udp_pct()),
        ],
        vec!["ARP".into(), stats.arp_packets.to_string(), "-".into()],
        vec![
            "ICMP".into(),
            stats.icmp_packets.to_string(),
            "-".into(),
        ],
        vec![
            "HTTP 请求".into(),
            stats.http_requests.to_string(),
            "-".into(),
        ],
        vec![
            "HTTP 响应".into(),
            stats.http_responses.to_string(),
            "-".into(),
        ],
        vec![
            "三次握手".into(),
            stats.tcp_handshakes.to_string(),
            "-".into(),
        ],
    ];
    let header = vec![
        "类型".to_string(),
        "数量".to_string(),
        "占比".to_string(),
    ];
    println!("{}", render_table(&header, &rows));

    let mut rows2: Vec<Vec<String>> = Vec::new();
    // TCP 标志位
    for (name, val) in [
        ("SYN", stats.tcp_syn),
        ("SYN+ACK", stats.tcp_synack),
        ("ACK", stats.tcp_ack),
        ("PSH", stats.tcp_psh),
        ("FIN", stats.tcp_fin),
        ("RST", stats.tcp_rst),
    ] {
        rows2.push(vec![name.into(), val.to_string()]);
    }
    let header2: Vec<String> = vec!["标志位".into(), "数量".into()];
    println!("\nTCP 标志位分布:");
    println!(
        "{}",
        render_table(&header2, &rows2)
    );
    Ok(())
}

/// 导出所有 TCP 流到指定目录
pub fn export_tcp_streams(file: &str, out_dir: &str) -> Result<usize> {
    let packets = parse_pcap(file)?;
    let streams = crate::stats::extract_tcp_streams(&packets);
    std::fs::create_dir_all(out_dir)?;
    let mut n = 0usize;
    for (i, stream) in streams.iter().enumerate() {
        let text = crate::stats::export_stream_to_text(stream);
        let path = format!(
            "{}/stream_{}_{}_{}.txt",
            out_dir, i, stream.client_ip.replace('.', "_"), stream.client_port
        );
        std::fs::write(&path, &text)?;
        n += 1;
    }
    println!("{} 导出 {} 个 TCP 流到 {}", "完成".green(), n, out_dir.cyan());
    Ok(n)
}

/// 展示三次握手时间线
pub fn print_handshake_timelines(file: &str, limit: Option<usize>) -> Result<()> {
    let packets = parse_pcap(file)?;
    let timelines = crate::stats::extract_handshake_timelines(&packets);
    let total = timelines.len();
    let shown = limit.unwrap_or(usize::MAX).min(total);
    println!(
        "\n=== 三次握手时间线 ({} 条, 显示 {} 条) ===",
        total, shown
    );
    for tl in timelines.iter().take(shown) {
        let status = if tl.complete { "✅" } else { "❌" };
        println!("{} {} [{}]", status, tl.stream_id.cyan(), tl.complete);
        for ev in &tl.events {
            println!(
                "  [{:.3}s] {} {} ({})",
                ev.timestamp,
                ev.direction,
                ev.description,
                ev.flags
            );
        }
    }
    Ok(())
}
