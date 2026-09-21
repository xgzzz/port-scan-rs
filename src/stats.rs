//! 协议统计、TCP 流重组、TCP 握手时间线
//!
//! 用于 pcap 文件的深度分析：
//! - compute_stats: 协议层 + TCP 标志位统计
//! - extract_tcp_streams: 按 5 元组重组 TCP 流
//! - extract_handshake_timelines: 三次握手时间线
//! - export_stream_to_text: 流导出为可读文本

use crate::parser::ParsedPacket;
use serde::Serialize;
use std::collections::HashMap;

/// 协议层统计
#[derive(Default, Serialize, Clone, Debug)]
pub struct ProtocolStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub arp_packets: u64,
    pub icmp_packets: u64,
    pub other_packets: u64,
    pub http_requests: u64,
    pub http_responses: u64,
    pub tcp_syn: u64,
    pub tcp_ack: u64,
    pub tcp_fin: u64,
    pub tcp_rst: u64,
    pub tcp_psh: u64,
    pub tcp_synack: u64,
    pub tcp_handshakes: u64,
    pub flow_count: u64,
}

impl ProtocolStats {
    pub fn tcp_pct(&self) -> f64 {
        if self.total_packets == 0 {
            0.0
        } else {
            self.tcp_packets as f64 / self.total_packets as f64 * 100.0
        }
    }
    pub fn udp_pct(&self) -> f64 {
        if self.total_packets == 0 {
            0.0
        } else {
            self.udp_packets as f64 / self.total_packets as f64 * 100.0
        }
    }
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct TcpStream {
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub start_time: f64,
    pub end_time: f64,
    pub client_data: Vec<u8>,
    pub server_data: Vec<u8>,
    pub client_bytes: u32,
    pub server_bytes: u32,
    pub handshake_ok: bool,
    pub has_http: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct HandshakeTimeline {
    pub stream_id: String,
    pub events: Vec<HandshakeEvent>,
    pub complete: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct HandshakeEvent {
    pub timestamp: f64,
    pub seq: u64,
    pub direction: String,
    pub flags: String,
    pub description: String,
}

fn ip_to_u32(s: &str) -> u32 {
    s.parse::<std::net::Ipv4Addr>()
        .map(|a| u32::from(a))
        .unwrap_or(0)
}

fn u32_to_ip(v: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xFF,
        (v >> 16) & 0xFF,
        (v >> 8) & 0xFF,
        v & 0xFF
    )
}

/// 计算协议统计
pub fn compute_stats(packets: &[ParsedPacket]) -> ProtocolStats {
    let mut s = ProtocolStats::default();
    let mut flows: std::collections::HashSet<(u32, u16, u32, u16, u8)> =
        std::collections::HashSet::new();
    // 记录出现过 SYN / SYN+ACK 的流，用于统计真正的三次握手次数
    let mut syn_flows: std::collections::HashSet<FlowKey> = std::collections::HashSet::new();
    let mut synack_flows: std::collections::HashSet<FlowKey> = std::collections::HashSet::new();

    for p in packets {
        s.total_packets += 1;
        s.total_bytes += p.payload_size as u64;

        match p.protocol.as_str() {
            "TCP" => {
                s.tcp_packets += 1;
                if let Some(flags) = &p.tcp_flags {
                    let syn = flags.contains("SYN");
                    let ack = flags.contains("ACK");
                    if syn && ack {
                        s.tcp_synack += 1;
                    } else if syn {
                        s.tcp_syn += 1;
                    }
                    if ack {
                        s.tcp_ack += 1;
                    }
                    if flags.contains("FIN") {
                        s.tcp_fin += 1;
                    }
                    if flags.contains("RST") {
                        s.tcp_rst += 1;
                    }
                    if flags.contains("PSH") {
                        s.tcp_psh += 1;
                    }
                    if syn {
                        if let (Some(si), Some(sp), Some(di), Some(dp)) =
                            (&p.src_ip, p.src_port, &p.dst_ip, p.dst_port)
                        {
                            let key = flow_key(ip_to_u32(si), sp, ip_to_u32(di), dp);
                            if ack {
                                synack_flows.insert(key);
                            } else {
                                syn_flows.insert(key);
                            }
                        }
                    }
                }
            }
            "UDP" => s.udp_packets += 1,
            "ARP" => s.arp_packets += 1,
            _ => {
                if p.protocol.contains("ICMP") {
                    s.icmp_packets += 1;
                } else {
                    s.other_packets += 1;
                }
            }
        }

        if let Some(h) = &p.http {
            if h.method == "RESPONSE" {
                s.http_responses += 1;
            } else {
                s.http_requests += 1;
            }
        }

        if p.src_ip.is_some() && p.dst_ip.is_some() && p.src_port.is_some() {
            let proto: u8 = match p.protocol.as_str() {
                "TCP" => 6,
                "UDP" => 17,
                _ => 0,
            };
            let sip = ip_to_u32(p.src_ip.as_ref().unwrap());
            let dip = ip_to_u32(p.dst_ip.as_ref().unwrap());
            flows.insert((sip, p.src_port.unwrap(), dip, p.dst_port.unwrap_or(0), proto));
        }
    }
    s.flow_count = flows.len() as u64;
    // 三次握手：同一条流上同时观察到 SYN 与 SYN+ACK，而不是把两种包的个数简单相加
    s.tcp_handshakes = syn_flows.intersection(&synack_flows).count() as u64;
    s
}

/// 5 元组 key
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct FlowKey(u32, u16, u32, u16, u8);

/// 把双向报文归一到同一条流：端口小的一端在前，端口相同时再按 IP 排序
fn flow_key(aip: u32, aport: u16, bip: u32, bport: u16) -> FlowKey {
    if (aport, aip) <= (bport, bip) {
        FlowKey(aip, aport, bip, bport, 6)
    } else {
        FlowKey(bip, bport, aip, aport, 6)
    }
}

/// 重组 TCP 流
pub fn extract_tcp_streams(packets: &[ParsedPacket]) -> Vec<TcpStream> {
    let mut maps: HashMap<FlowKey, Vec<&ParsedPacket>> = HashMap::new();
    for p in packets {
        if p.protocol != "TCP" {
            continue;
        }
        if let (Some(src_ip), Some(dst_ip), Some(sp), Some(dp)) =
            (&p.src_ip, &p.dst_ip, p.src_port, p.dst_port)
        {
            let a = ip_to_u32(src_ip);
            let b = ip_to_u32(dst_ip);
            let key = if sp < dp {
                FlowKey(a, sp, b, dp, 6)
            } else {
                FlowKey(b, dp, a, sp, 6)
            };
            maps.entry(key).or_default().push(p);
        }
    }

    let mut streams = Vec::new();
    for (key, pkts) in maps.into_iter() {
        let (cip, cport, sip, sport) = (key.0, key.1, key.2, key.3);
        let mut sorted: Vec<&ParsedPacket> = pkts;
        sorted.sort_by(|a, b| a.seq.cmp(&b.seq));

        let mut stream = TcpStream {
            client_ip: u32_to_ip(cip),
            client_port: cport,
            server_ip: u32_to_ip(sip),
            server_port: sport,
            start_time: sorted.first().map(|p| p.timestamp).unwrap_or(0.0),
            end_time: sorted.last().map(|p| p.timestamp).unwrap_or(0.0),
            ..Default::default()
        };

        for p in &sorted {
            let flags = p.tcp_flags.clone().unwrap_or_default();
            let is_syn = flags.contains("SYN") && !flags.contains("ACK");
            if is_syn {
                stream.handshake_ok = true;
            }
            if p.http.is_some() {
                stream.has_http = true;
            }
            if p.payload_size > 0 {
                let payload: Vec<u8> = p
                    .http
                    .as_ref()
                    .map(|h| h.body.as_bytes().to_vec())
                    .unwrap_or_default();
                if p.src_port < p.dst_port {
                    stream.client_data.extend_from_slice(&payload);
                    stream.client_bytes += payload.len() as u32;
                } else {
                    stream.server_data.extend_from_slice(&payload);
                    stream.server_bytes += payload.len() as u32;
                }
            }
        }

        streams.push(stream);
    }
    streams
}

/// 提取 TCP 握手时间线
pub fn extract_handshake_timelines(packets: &[ParsedPacket]) -> Vec<HandshakeTimeline> {
    let mut by_flow: HashMap<FlowKey, Vec<HandshakeEvent>> = HashMap::new();

    for p in packets {
        if p.protocol != "TCP" {
            continue;
        }
        let flags = p.tcp_flags.clone().unwrap_or_default();
        let is_syn = flags.contains("SYN") && !flags.contains("ACK");
        let is_synack = flags.contains("SYN") && flags.contains("ACK");
        let is_ack_only = flags == "ACK";
        if !is_syn && !is_synack && !is_ack_only {
            continue;
        }
        let (src_ip, src_port, dst_ip, dst_port) =
            match (&p.src_ip, p.src_port, &p.dst_ip, p.dst_port) {
                (Some(si), Some(sp), Some(di), Some(dp)) => (ip_to_u32(si), sp, ip_to_u32(di), dp),
                _ => continue,
            };
        let key = if src_port < dst_port {
            FlowKey(src_ip, src_port, dst_ip, dst_port, 6)
        } else {
            FlowKey(dst_ip, dst_port, src_ip, src_port, 6)
        };

        let ev = HandshakeEvent {
            timestamp: p.timestamp,
            seq: p.seq,
            direction: if is_syn || is_ack_only {
                "C->S".into()
            } else {
                "S->C".into()
            },
            flags: flags.clone(),
            description: if is_syn {
                "SYN".into()
            } else if is_synack {
                "SYN+ACK".into()
            } else {
                "ACK (3rd)".into()
            },
        };
        by_flow.entry(key).or_default().push(ev);
    }

    let mut result: Vec<HandshakeTimeline> = Vec::new();
    for (key, events) in by_flow.into_iter() {
        let complete = events.iter().any(|e| e.description == "ACK (3rd)");
        let id = format!(
            "{}:{} <-> {}:{}",
            u32_to_ip(key.0),
            key.1,
            u32_to_ip(key.2),
            key.3
        );
        result.push(HandshakeTimeline {
            stream_id: id,
            events,
            complete,
        });
    }
    result
}

/// 将 TCP 流导出为可读文本
pub fn export_stream_to_text(stream: &TcpStream) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "=== TCP Stream {}:{} <-> {}:{} ===\n",
        stream.client_ip, stream.client_port, stream.server_ip, stream.server_port
    ));
    let start_ms = (stream.start_time * 1000.0) as u64;
    let end_ms = (stream.end_time * 1000.0) as u64;
    out.push_str(&format!(
        "Start: {}ms  End: {}ms\n",
        start_ms, end_ms
    ));
    out.push_str(&format!(
        "Client -> Server: {} bytes\n",
        stream.client_bytes
    ));
    out.push_str(&format!(
        "Server -> Client: {} bytes\n",
        stream.server_bytes
    ));
    out.push_str("\n----- Client Data -----\n");
    out.push_str(&String::from_utf8_lossy(&stream.client_data));
    out.push_str("\n\n----- Server Data -----\n");
    out.push_str(&String::from_utf8_lossy(&stream.server_data));
    out.push('\n');
    out
}
