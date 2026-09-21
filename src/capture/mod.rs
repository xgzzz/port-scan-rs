pub mod netif;

use anyhow::Result;
use colored::*;

#[cfg(not(feature = "pcap"))]
use std::io::{Read, Write};

pub use netif::print_interfaces;

/// 抓包参数
pub struct CaptureOpts {
    /// 网卡名（pcap 模式下必填）
    pub interface: Option<String>,
    /// BPF 过滤表达式，如 `tcp port 80`
    pub filter: Option<String>,
    /// pcap 输出路径
    pub output: String,
    /// 抓够多少字节后停止，0 表示不限
    pub max_bytes: u32,
    /// 实时打印每个包的解析预览
    pub preview: bool,
    /// 抓够多少个包后停止，0 表示不限
    pub count: u64,
    /// 是否把抓到的包写入 pcap 文件
    pub save: bool,
}

/// 抓取流量。
/// - 启用 `pcap` 特性时：抓取指定网卡流量，支持 BPF 过滤、实时预览与落盘
/// - 未启用时：fallback 到本地 TCP 监听，将请求记录为文本日志
pub fn capture(opts: CaptureOpts) -> Result<()> {
    #[cfg(feature = "pcap")]
    {
        return capture_with_pcap(opts);
    }

    #[cfg(not(feature = "pcap"))]
    {
        capture_fallback(opts)
    }
}

#[cfg(feature = "pcap")]
fn capture_with_pcap(opts: CaptureOpts) -> Result<()> {
    let interface = match &opts.interface {
        Some(name) => name.clone(),
        None => {
            let ifaces = netif::list_interfaces()?;
            println!("{}", "可用网卡:".blue());
            for f in &ifaces {
                println!("  {} - {}", f.name.green(), f.description);
            }
            return Err(anyhow::anyhow!(
                "请指定网卡 --interface（可用 `ifaces` 子命令查看全部网卡）"
            ));
        }
    };

    let save_path = if opts.save {
        Some(std::path::PathBuf::from(&opts.output))
    } else {
        None
    };

    // 抓包在后台线程里跑，主线程消费预览事件，CLI 与 GUI 共用同一套引擎
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = netif::start_capture(
        &interface,
        opts.filter.clone(),
        save_path.clone(),
        tx,
    )?;

    println!("{}", "按 Ctrl+C 停止".dimmed());

    let mut count = 0u64;
    let mut bytes = 0u64;
    while let Ok(event) = rx.recv() {
        match event {
            netif::IfaceEvent::Status(msg) => println!("{} {}", "[抓包]".blue(), msg),
            netif::IfaceEvent::Packet(row) => {
                count += 1;
                bytes += row.length as u64;

                if opts.preview {
                    println!("{}", netif::format_preview(&row));
                } else if count % 100 == 0 {
                    println!("已捕获 {} 包 / {} 字节", count, bytes);
                }

                if opts.count > 0 && count >= opts.count {
                    println!("\n已达到包数上限 {}，停止", opts.count);
                    break;
                }
                if opts.max_bytes > 0 && bytes >= opts.max_bytes as u64 {
                    println!("\n已达到最大字节数，停止");
                    break;
                }
            }
        }
    }

    handle.stop();
    let (total_packets, total_bytes) = handle.counters();
    match &save_path {
        Some(path) => println!(
            "{} 共 {} 包 / {} 字节，已写入 {}",
            "完成".green(),
            total_packets,
            total_bytes,
            path.display()
        ),
        None => println!(
            "{} 共 {} 包 / {} 字节（未写文件）",
            "完成".green(),
            total_packets,
            total_bytes
        ),
    }
    Ok(())
}

#[cfg(not(feature = "pcap"))]
fn capture_fallback(opts: CaptureOpts) -> Result<()> {
    let output = opts.output.as_str();
    let preview = opts.preview;
    let save = opts.save;
    let max_bytes = opts.max_bytes as u64;
    let max_packets = if opts.count > 0 { opts.count } else { 1000 };

    if opts.interface.is_some() || opts.filter.is_some() {
        println!(
            "{}",
            "(--interface / --filter 仅在启用 pcap 特性编译时生效)".yellow()
        );
    }
    println!(
        "{} 未启用 pcap 特性，退化为本地 TCP 监听（127.0.0.1:8888）",
        "提示".yellow()
    );
    println!(
        "{} 访问 http://127.0.0.1:8888 即可产生流量；网卡抓包请用 cargo build --features pcap",
        "说明:".cyan()
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:8888")?;
    if save {
        // 先建出空文件，保证结束时文件一定存在
        let _ = std::fs::File::create(output)?;
    }
    let mut count = 0u64;
    let mut bytes = 0u64;

    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            continue;
        }
        let now = chrono::Utc::now();
        if save {
            let log_line = format!("{} {} {}\n", now, n, hex::encode(&buf[..n]));
            std::fs::OpenOptions::new()
                .append(true)
                .open(output)?
                .write_all(log_line.as_bytes())?;
        }
        count += 1;
        bytes += n as u64;

        if preview {
            println!(
                "#{:<6} {:<12} {:<24} {:<14} {:>6} B  {}",
                count,
                now.format("%H:%M:%S%.3f"),
                "127.0.0.1:8888",
                "TCP",
                n,
                hex::encode(&buf[..n.min(48)])
            );
        } else {
            println!("已捕获 {} 包 ({} 字节)", count, n);
        }

        if count >= max_packets {
            println!("达到包数上限 {}，停止", max_packets);
            break;
        }
        if max_bytes > 0 && bytes >= max_bytes {
            println!("达到最大字节数 {}，停止", max_bytes);
            break;
        }
    }

    if save {
        println!("{} 共 {} 包，已写入 {}", "完成".green(), count, output.cyan());
    } else {
        println!("{} 共 {} 包（未写文件）", "完成".green(), count);
    }
    Ok(())
}
