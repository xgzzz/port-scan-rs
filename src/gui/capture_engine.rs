//! GUI 抓包引擎：后台线程监听 127.0.0.1:8888，实时识别 HTTP 请求并通过 mpsc 回传日志。
//!
//! 设计：
//! - `CaptureEngine::start()` 在后台线程中启动 TCP 监听
//! - 每收到数据，尝试识别 HTTP 请求/响应，生成日志行
//! - 通过 mpsc::channel 回传给 GUI 主线程，GUI 每帧 poll
//! - `CaptureEngine::stop()` 设置标志，线程自然退出

use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

/// 一条抓包日志（GUI 显示用）
#[derive(Clone, Debug)]
pub enum CaptureLog {
    /// 状态消息（开始/停止/错误等）
    Status(String),
    /// 原始数据包
    Packet {
        seq: u64,
        bytes: u32,
        preview: String,
    },
    /// 识别到的 HTTP 请求
    HttpRequest {
        seq: u64,
        method: String,
        path: String,
        headers_preview: String,
    },
    /// 识别到的 HTTP 响应
    HttpResponse {
        seq: u64,
        status: String,
        headers_preview: String,
    },
}

/// 抓包引擎句柄（跨线程共享）
#[derive(Clone)]
pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    pub counter: Arc<AtomicU64>,
}

/// 抓包引擎（GUI 用，非阻塞）
pub struct CaptureEngine {
    handle: Option<CaptureHandle>,
    rx: Option<mpsc::Receiver<CaptureLog>>,
    port: u16,
}

impl Default for CaptureEngine {
    fn default() -> Self {
        Self::new(8888)
    }
}

impl CaptureEngine {
    pub fn new(port: u16) -> Self {
        Self {
            handle: None,
            rx: None,
            port,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 启动后台监听。如果端口被占用则返回错误日志。
    pub fn start(&mut self) {
        if self.handle.is_some() {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let (tx, rx) = mpsc::channel();
        let port = self.port;

        let stop_clone = Arc::clone(&stop);
        let counter_clone = Arc::clone(&counter);
        std::thread::spawn(move || {
            let tx = tx;
            let stop = stop_clone;
            let counter = counter_clone;
            capture_loop(port, &stop, &counter, &tx);
        });

        self.handle = Some(CaptureHandle { stop, counter });
        self.rx = Some(rx);
    }

    /// 停止监听（不阻塞，线程会自然退出）
    pub fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.stop.store(true, Ordering::SeqCst);
        }
        self.rx = None;
    }

    /// 非阻塞获取一条日志（每帧调用）
    pub fn poll(&mut self) -> Option<CaptureLog> {
        self.rx.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(l) => Some(l),
            Err(_) => None,
        })
    }

    /// 已捕获包数
    pub fn captured_count(&self) -> u64 {
        self.handle
            .as_ref()
            .map(|h| h.counter.load(Ordering::SeqCst))
            .unwrap_or(0)
    }
}

/// 后台监听循环
fn capture_loop(
    port: u16,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<CaptureLog>,
) {
    let addr = format!("127.0.0.1:{}", port);
    let listener: TcpListener = match std::net::TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            let _ = tx.send(CaptureLog::Status(format!(
                "❌ 监听 {} 失败: {}",
                addr, e
            )));
            return;
        }
    };

    let _ = tx.send(CaptureLog::Status(format!(
        "▶️ 开始监听 {}，可访问该端口产生流量",
        addr
    )));

    // 设置非阻塞以便检查 stop 标志
    let _ = listener.set_nonblocking(true);

    let buf = [0u8; 8192];
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        // 非阻塞 accept：用短 sleep 轮询
        let accepted = loop {
            match listener.accept() {
                Ok(stream) => break Some(stream),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break None;
                }
                Err(e) => {
                    let _ = tx.send(CaptureLog::Status(format!(
                        "⚠️ accept 错误: {}",
                        e
                    )));
                    break None;
                }
            }
        };

        if let Some((mut stream, _addr)) = accepted {
            let _ = tx.send(CaptureLog::Status(
                "🔗 新连接".to_string(),
            ));
            capture_connection(&mut stream, stop, counter, tx, &buf);
        } else {
            // 暂无连接，短暂休眠后检查 stop
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    let _ = tx.send(CaptureLog::Status(
        "⏹ 已停止监听".to_string(),
    ));
}

/// 处理单个连接的数据
fn capture_connection(
    stream: &mut std::net::TcpStream,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<CaptureLog>,
    buf: &[u8],
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let mut read_buf = [0u8; 8192];
        let n = match stream.read(&mut read_buf) {
            Ok(0) => break, // 对端关闭
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue; // 超时，继续
            }
            Err(e) => {
                let _ = tx.send(CaptureLog::Status(format!("⚠️ 读取错误: {}", e)));
                break;
            }
        };

        let seq = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let data = &read_buf[..n];

        // 识别 HTTP
        if let Some(http_info) =
            crate::parser::parse_http_payload(&String::from_utf8_lossy(data))
        {
            if http_info.method == "RESPONSE" {
                let headers = extract_headers_preview(data, n);
                let status = http_info
                    .status
                    .clone()
                    .unwrap_or_else(|| "???".into());
                let _ = tx.send(CaptureLog::HttpResponse {
                    seq,
                    status,
                    headers_preview: headers,
                });
            } else {
                let headers = extract_headers_preview(data, n);
                let _ = tx.send(CaptureLog::HttpRequest {
                    seq,
                    method: http_info.method.clone(),
                    path: http_info.path.clone(),
                    headers_preview: headers,
                });
            }
        } else {
            // 非 HTTP，显示原始预览
            let preview = make_preview(data);
            let _ = tx.send(CaptureLog::Packet {
                seq,
                bytes: n as u32,
                preview,
            });
        }

        let _ = buf; // 保持参数一致
    }
}

/// 提取 HTTP 请求头预览（前 5 行）
fn extract_headers_preview(data: &[u8], n: usize) -> String {
    let text = String::from_utf8_lossy(&data[..n]);
    let lines: Vec<&str> = text.lines().take(6).collect();
    lines.join(" ")
}

/// 生成数据预览（UTF-8 安全截断）
fn make_preview(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    let preview: String = text
        .chars()
        .filter(|c| c.is_whitespace() || c.is_ascii_graphic() || c.is_ascii_alphabetic())
        .take(60)
        .collect();
    if text.len() > 60 {
        format!("{}…", preview)
    } else {
        preview
    }
}
