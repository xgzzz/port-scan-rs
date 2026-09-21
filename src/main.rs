use clap::{Parser, Subcommand};
use colored::*;
use port_scan_rs::{capture, gui, parser, scanner};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "port-scan-rs")]
#[command(version)]
#[command(about = "本地端口检测、抓包与抓包分析工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 扫描本机端口
    Local {
        /// 仅显示 LISTEN 端口
        #[arg(long, default_value_t = false)]
        listening: bool,
        /// 按进程名过滤（子串匹配）
        #[arg(long)]
        process: Option<String>,
        /// 按 PID 过滤
        #[arg(long)]
        pid: Option<u32>,
        /// 输出 JSON
        #[arg(long)]
        json: bool,
    },
    /// 扫描远程主机端口
    Scan {
        /// 目标主机（IP 或域名）
        host: String,
        /// 端口范围，如 "80,443,8080-8090"
        #[arg(long, default_value = "1-1024")]
        ports: String,
        /// 并发数
        #[arg(long, default_value_t = 50)]
        concurrency: usize,
        /// 扫描超时毫秒
        #[arg(long, default_value_t = 500)]
        timeout_ms: u64,
    },
    /// 抓包：选定网卡抓取流量，支持 BPF 过滤、实时预览与落盘
    Capture {
        /// 网卡名，先用 `ifaces` 子命令查看
        #[arg(long)]
        interface: Option<String>,
        /// BPF 过滤表达式，如 "tcp port 80"、"host 1.2.3.4 and udp"
        #[arg(long)]
        filter: Option<String>,
        /// 输出文件
        #[arg(short, long, default_value = "capture.pcap")]
        output: String,
        /// 最大捕获字节数，0 表示不限
        #[arg(long, default_value_t = 0)]
        max_bytes: u32,
        /// 实时打印每个包的解析预览
        #[arg(long, default_value_t = false)]
        preview: bool,
        /// 抓够 N 个包后自动停止，0 表示不限
        #[arg(long, default_value_t = 0)]
        count: u64,
        /// 只预览，不写 pcap 文件
        #[arg(long, default_value_t = false)]
        no_save: bool,
    },
    /// 列出本机网卡（网卡扫描）
    #[command(alias = "interfaces")]
    Ifaces {
        /// 输出 JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 解析 pcap 文件
    Analyze {
        /// pcap 文件路径
        file: String,
        /// 仅显示 TCP 包
        #[arg(long)]
        tcp: bool,
        /// 仅显示 UDP 包
        #[arg(long)]
        udp: bool,
        /// 仅显示 HTTP 请求
        #[arg(long)]
        http: bool,
        /// 导出 HTTP 会话为 JSON
        #[arg(long)]
        http_json: bool,
        /// 限制显示条数
        #[arg(long)]
        limit: Option<usize>,
        /// 显示协议统计（TCP/UDP/HTTP/握手）
        #[arg(long)]
        stats: bool,
        /// 显示三次握手时间线
        #[arg(long)]
        handshakes: bool,
        /// 导出所有 TCP 流到指定目录
        #[arg(long)]
        export_streams: Option<String>,
    },
    /// 启动 GUI 桌面版
    Gui,
}

#[tokio::main]
async fn main() -> ExitCode {
    // 无参数时默认启动 GUI（双击 .exe 的场景）
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        // 双击控制台程序时系统会开一个黑窗口，这里把它收起来（仅当这个控制台是我们自己的）
        gui::hide_console_if_owned();
        gui::run_gui()
    } else {
        let cli = Cli::parse();
        match cli.command {
            Command::Local {
                listening,
                process,
                pid,
                json,
            } => match scanner::scan_local(listening, process, pid, json) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{} {}", "错误:".red(), e.to_string().red());
                    ExitCode::FAILURE
                }
            },
            Command::Scan {
                host,
                ports,
                concurrency,
                timeout_ms,
            } => match scanner::scan_remote(&host, &ports, concurrency, timeout_ms).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{} {}", "错误:".red(), e.to_string().red());
                    ExitCode::FAILURE
                }
            },
            Command::Capture {
                interface,
                filter,
                output,
                max_bytes,
                preview,
                count,
                no_save,
            } => match capture::capture(capture::CaptureOpts {
                interface,
                filter,
                output,
                max_bytes,
                preview,
                count,
                save: !no_save,
            }) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{} {}", "错误:".red(), e.to_string().red());
                    ExitCode::FAILURE
                }
            },
            Command::Ifaces { json } => match capture::print_interfaces(json) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("{} {}", "错误:".red(), e.to_string().red());
                    ExitCode::FAILURE
                }
            },
            Command::Analyze {
                file,
                tcp,
                udp,
                http,
                http_json,
                limit,
                stats,
                handshakes,
                export_streams,
            } => {
                if let Some(dir) = export_streams {
                    if let Err(e) = parser::export_tcp_streams(&file, &dir) {
                        eprintln!("{} {}", "错误:".red(), e.to_string().red());
                        return ExitCode::FAILURE;
                    }
                }
                if stats {
                    if let Err(e) = parser::print_protocol_stats(&file) {
                        eprintln!("{} {}", "错误:".red(), e.to_string().red());
                        return ExitCode::FAILURE;
                    }
                }
                if handshakes {
                    if let Err(e) = parser::print_handshake_timelines(&file, limit) {
                        eprintln!("{} {}", "错误:".red(), e.to_string().red());
                        return ExitCode::FAILURE;
                    }
                }
                match parser::analyze(&file, tcp, udp, http, http_json, limit) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("{} {}", "错误:".red(), e.to_string().red());
                        ExitCode::FAILURE
                    }
                }
            }
            Command::Gui => {
                gui::run_gui()
            }
        }
    }
}
