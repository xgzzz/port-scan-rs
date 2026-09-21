//! GUI 界面层：左侧导航 + 卡片式内容区。
//!
//! 这里只负责「怎么显示、怎么交互」，后台任务与抓包引擎的逻辑与之前保持一致：
//! 所有耗时操作都丢到线程里，通过 `mpsc` 通道回传，`poll_tasks()` 每帧非阻塞收取。
//!
//! 视觉部分统一走 `crate::gui::theme`：配色、间距、圆角、间距与可复用组件都在那里。

use egui::{
    Align, CentralPanel, Color32, Frame, Grid, Layout, Margin, ScrollArea, SidePanel, Stroke,
    TextEdit, TopBottomPanel, Ui,
};

use crate::capture::netif::{self, IfaceCaptureHandle, IfaceEvent, IfaceInfo, PreviewRow};
use crate::gui::capture_engine::{CaptureEngine, CaptureLog};
use crate::gui::theme;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::Instant;

/// 网卡抓包预览最多保留的行数
const IFACE_MAX_ROWS: usize = 2000;
/// 预览表格每帧最多渲染的行数
const IFACE_MAX_SHOWN: usize = 500;
/// 回环监听日志区最多渲染的行数
const LOOPBACK_MAX_SHOWN: usize = 200;
/// 包列表硬上限：即使选「全部」也只渲染这么多行，避免超大 pcap 一次渲染几十万行卡死界面
const PACKET_ROWS_HARD_CAP: usize = 20_000;

/// 后台任务类型
enum TaskResult {
    LocalPorts(Result<Vec<crate::scanner::PortEntry>, String>),
    RemoteScan {
        /// (端口, 服务名, 是否开放, banner)
        results: Result<Vec<ScanRow>, String>,
    },
    Ifaces(Result<Vec<IfaceInfo>, String>),
}

/// 远程扫描的单条结果
#[derive(Clone, Debug)]
pub struct ScanRow {
    port: u16,
    service: String,
    open: bool,
    banner: String,
}

pub struct App {
    // 外观
    dark: bool,
    theme_applied: Option<bool>,

    // 抓包分析
    pub loaded_file: Option<String>,
    pub packets: Option<std::sync::Arc<Vec<crate::parser::ParsedPacket>>>,
    pub stats: Option<std::sync::Arc<crate::stats::ProtocolStats>>,
    pub streams: Option<std::sync::Arc<Vec<crate::stats::TcpStream>>>,
    pub timelines: Option<std::sync::Arc<Vec<crate::stats::HandshakeTimeline>>>,
    pub last_error: Option<String>,
    pub active_tab: Tab,
    /// 包列表的文本过滤
    pub analyze_filter: String,
    /// 包列表显示上限，0 表示全部
    pub analyze_limit: usize,

    // 远程扫描
    pub scan_host: String,
    pub scan_ports: String,
    pub scan_rows: Option<Vec<ScanRow>>,
    pub scan_error: Option<String>,
    pub scanning: bool,
    pub scan_concurrency: usize,
    pub scan_timeout_ms: u64,

    // 本机端口（缓存 + 后台线程）
    pub local_data: Option<Vec<crate::scanner::PortEntry>>,
    pub local_loading: bool,
    pub local_error: Option<String>,
    pub local_last_updated: Option<Instant>,
    /// 本机端口文本过滤（端口 / 地址 / 进程）
    pub local_filter: String,
    /// 只看 LISTEN
    pub local_only_listen: bool,
    /// 协议过滤：0 全部 / 1 TCP / 2 UDP
    pub local_proto: usize,

    // 抓包（实时）
    pub capture_enabled: bool,
    capture_engine: CaptureEngine,
    capture_logs: Vec<String>,   // 展示用的日志行
    capture_port_input: String,
    capture_http_count: u64,
    pub loopback_auto_scroll: bool,

    // 网卡抓包（真实网卡，需 pcap 特性）
    pub capture_mode: CaptureMode,
    pub ifaces: Vec<IfaceInfo>,
    pub iface_selected: usize,
    pub iface_filter: String,
    pub iface_display_filter: String,
    pub iface_rows: VecDeque<PreviewRow>,
    pub iface_save: bool,
    pub iface_save_path: String,
    pub iface_error: Option<String>,
    pub iface_status: String,
    pub iface_running: bool,
    pub iface_auto_scroll: bool,
    pub iface_loading: bool,
    iface_handle: Option<IfaceCaptureHandle>,
    iface_rx: Option<mpsc::Receiver<IfaceEvent>>,

    // 后台任务结果通道
    task_rx: Option<mpsc::Receiver<TaskResult>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Analyze,
    Local,
    Scan,
    Capture,
}

/// 抓包页的两种模式
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// 真实网卡抓包（BPF 过滤 + 实时预览）
    Iface,
    /// 回环 TCP 监听，用于调试 HTTP 请求
    Loopback,
}

impl Default for App {
    fn default() -> Self {
        Self {
            dark: true,
            theme_applied: None,
            loaded_file: None,
            packets: None,
            stats: None,
            streams: None,
            timelines: None,
            last_error: None,
            active_tab: Tab::Analyze,
            analyze_filter: String::new(),
            analyze_limit: 100,
            scan_host: "127.0.0.1".into(),
            scan_ports: "80,443,3306,8080".into(),
            scan_rows: None,
            scan_error: None,
            scanning: false,
            scan_concurrency: 64,
            scan_timeout_ms: 500,
            local_data: None,
            local_loading: false,
            local_error: None,
            local_last_updated: None,
            local_filter: String::new(),
            local_only_listen: true,
            local_proto: 0,
            capture_enabled: false,
            capture_engine: CaptureEngine::default(),
            capture_logs: Vec::new(),
            capture_port_input: "8888".into(),
            capture_http_count: 0,
            loopback_auto_scroll: true,
            capture_mode: if netif::PCAP_ENABLED {
                CaptureMode::Iface
            } else {
                CaptureMode::Loopback
            },
            ifaces: Vec::new(),
            iface_selected: 0,
            iface_filter: String::new(),
            iface_display_filter: String::new(),
            iface_rows: VecDeque::new(),
            iface_save: false,
            iface_save_path: "capture.pcap".into(),
            iface_error: None,
            iface_status: String::new(),
            iface_running: false,
            iface_auto_scroll: true,
            iface_loading: false,
            iface_handle: None,
            iface_rx: None,
            task_rx: None,
        }
    }
}

impl App {
    pub fn load_pcap(&mut self, path: &str) {
        match crate::parser::parse_pcap(path) {
            Ok(packets) => {
                let stats = crate::stats::compute_stats(&packets);
                let streams = crate::stats::extract_tcp_streams(&packets);
                let timelines = crate::stats::extract_handshake_timelines(&packets);
                self.packets = Some(std::sync::Arc::new(packets));
                self.stats = Some(std::sync::Arc::new(stats));
                self.streams = Some(std::sync::Arc::new(streams));
                self.timelines = Some(std::sync::Arc::new(timelines));
                self.loaded_file = Some(path.to_string());
                self.last_error = None;
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
            }
        }
    }

    /// 弹出文件选择框并载入
    fn pick_pcap(&mut self) {
        if let Some(fp) = rfd::FileDialog::new().pick_file() {
            let path = fp.to_string_lossy().to_string();
            self.loaded_file = Some(path.clone());
            self.load_pcap(&path);
        }
    }

    /// 启动本机端口后台扫描
    fn start_local_scan(&mut self) {
        if self.local_loading {
            return;
        }
        self.local_loading = true;
        self.local_error = None;
        let (tx, rx) = mpsc::channel::<TaskResult>();
        // 如果有旧 rx 还挂着，替换掉（旧的线程结果会丢失，没关系）
        self.task_rx = Some(rx);
        std::thread::spawn(move || {
            let result = match crate::scanner::scan_local_ports() {
                Ok(entries) => Ok(entries),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(TaskResult::LocalPorts(result));
        });
    }

    /// 启动远程扫描后台线程
    fn start_remote_scan(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.scan_rows = None;
        self.scan_error = None;
        let host = self.scan_host.clone();
        let ports = self.scan_ports.clone();
        let concurrency = self.scan_concurrency;
        let timeout = self.scan_timeout_ms;
        let (tx, rx) = mpsc::channel::<TaskResult>();
        self.task_rx = Some(rx);
        std::thread::spawn(move || {
            let result = match crate::scanner::scan_remote_inner_sync(
                &host,
                &ports,
                concurrency,
                timeout,
            ) {
                Ok(results) => Ok(results
                    .into_iter()
                    .map(|r| ScanRow {
                        port: r.port,
                        service: r.service.unwrap_or_default(),
                        open: r.open,
                        banner: r.banner.unwrap_or_default(),
                    })
                    .collect()),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(TaskResult::RemoteScan { results: result });
        });
    }

    /// 后台枚举网卡（网卡扫描）
    fn start_list_ifaces(&mut self) {
        if self.iface_loading {
            return;
        }
        self.iface_loading = true;
        self.iface_error = None;
        let (tx, rx) = mpsc::channel::<TaskResult>();
        self.task_rx = Some(rx);
        std::thread::spawn(move || {
            let result = netif::list_interfaces().map_err(|e| e.to_string());
            let _ = tx.send(TaskResult::Ifaces(result));
        });
    }

    /// 开始网卡抓包（BPF 过滤 + 可选落盘）
    fn start_iface_capture(&mut self) {
        if self.iface_running {
            return;
        }
        let iface = match self.ifaces.get(self.iface_selected) {
            Some(f) => f.name.clone(),
            None => {
                self.iface_error = Some("请先选择一块网卡".into());
                return;
            }
        };

        let save_path = if self.iface_save {
            let path = self.iface_save_path.trim();
            if path.is_empty() {
                self.iface_error = Some("请填写抓包文件的保存路径".into());
                return;
            }
            Some(std::path::PathBuf::from(path))
        } else {
            None
        };

        let (tx, rx) = mpsc::channel();
        match netif::start_capture(&iface, Some(self.iface_filter.clone()), save_path, tx) {
            Ok(handle) => {
                self.iface_handle = Some(handle);
                self.iface_rx = Some(rx);
                self.iface_running = true;
                self.iface_error = None;
                self.iface_rows.clear();
                self.iface_status = "启动中…".into();
            }
            Err(e) => {
                self.iface_error = Some(e.to_string());
                self.iface_running = false;
            }
        }
    }

    /// 停止网卡抓包
    fn stop_iface_capture(&mut self) {
        if let Some(handle) = self.iface_handle.take() {
            handle.stop();
        }
        // 丢掉接收端，抓包线程会在下一次发送失败时立即退出
        self.iface_rx = None;
        self.iface_running = false;
        self.iface_status = "已停止".into();
    }

    /// 开始回环监听（HTTP 调试）
    fn start_loopback(&mut self) {
        let port: u16 = self.capture_port_input.trim().parse().unwrap_or(8888);
        self.capture_engine = CaptureEngine::new(port);
        self.capture_engine.start();
        self.capture_logs.clear();
        self.capture_http_count = 0;
        self.capture_enabled = true;
    }

    /// 停止回环监听
    fn stop_loopback(&mut self) {
        self.capture_engine.stop();
        self.capture_enabled = false;
    }

    /// 收取网卡抓包的预览事件（非阻塞）
    fn poll_iface_events(&mut self) {
        let mut events = Vec::new();
        let mut disconnected = false;
        if let Some(rx) = &self.iface_rx {
            loop {
                match rx.try_recv() {
                    Ok(ev) => events.push(ev),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        for ev in events {
            match ev {
                IfaceEvent::Status(msg) => {
                    if msg.starts_with("抓包出错") {
                        self.iface_error = Some(msg.clone());
                    }
                    self.iface_status = msg;
                }
                IfaceEvent::Packet(row) => {
                    self.iface_rows.push_back(row);
                    while self.iface_rows.len() > IFACE_MAX_ROWS {
                        self.iface_rows.pop_front();
                    }
                }
            }
        }

        if disconnected {
            self.iface_rx = None;
            self.iface_running = false;
        }
    }

    /// 每帧检查后台任务结果（非阻塞）
    fn poll_tasks(&mut self) {
        // 1. 抓包引擎日志
        if self.capture_enabled {
            loop {
                match self.capture_engine.poll() {
                    Some(log) => self.push_capture_log(&log),
                    None => break,
                }
            }
        }

        // 2. 其他后台任务
        if let Some(rx) = self.task_rx.take() {
            loop {
                match rx.try_recv() {
                    Ok(TaskResult::LocalPorts(Ok(entries))) => {
                        self.local_data = Some(entries);
                        self.local_last_updated = Some(Instant::now());
                        self.local_loading = false;
                    }
                    Ok(TaskResult::LocalPorts(Err(e))) => {
                        self.local_error = Some(e);
                        self.local_loading = false;
                    }
                    Ok(TaskResult::RemoteScan { results }) => match results {
                        Ok(list) => {
                            self.scan_rows = Some(list);
                            self.scan_error = None;
                            self.scanning = false;
                        }
                        Err(e) => {
                            self.scan_error = Some(e);
                            self.scan_rows = None;
                            self.scanning = false;
                        }
                    },
                    Ok(TaskResult::Ifaces(Ok(list))) => {
                        self.ifaces = list;
                        self.iface_selected = 0;
                        self.iface_loading = false;
                    }
                    Ok(TaskResult::Ifaces(Err(e))) => {
                        self.iface_error = Some(e);
                        self.iface_loading = false;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        self.task_rx = Some(rx);
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.task_rx = None;
                        break;
                    }
                }
            }
        }

        // 3. 网卡抓包的实时预览事件
        self.poll_iface_events();
    }

    /// 将抓包日志推入显示列表
    fn push_capture_log(&mut self, log: &CaptureLog) {
        let line = match log {
            CaptureLog::Status(s) => format!("[状态] {}", s),
            CaptureLog::Packet { seq, bytes, preview } => {
                format!("[包#{}] ({} 字节) {}", seq, bytes, preview)
            }
            CaptureLog::HttpRequest { seq, method, path, headers_preview } => {
                self.capture_http_count += 1;
                format!(
                    "[HTTP请求#{}] {} {} | {}",
                    seq, method, path, headers_preview
                )
            }
            CaptureLog::HttpResponse { seq, status, headers_preview } => {
                format!("[HTTP响应#{}] {} | {}", seq, status, headers_preview)
            }
        };
        self.capture_logs.push(line);
        // 限制日志条数，避免内存增长
        if self.capture_logs.len() > 500 {
            self.capture_logs.drain(0..100);
        }
    }
}

// ---------------------------------------------------------------------------
// 顶层框架：顶栏 + 左侧导航 + 内容区
// ---------------------------------------------------------------------------

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 主题只在切换时重新应用一次
        if self.theme_applied != Some(self.dark) {
            theme::apply(ctx, self.dark);
            self.theme_applied = Some(self.dark);
        }

        // 每帧非阻塞检查后台任务
        self.poll_tasks();

        let p = theme::palette_ctx(ctx);

        TopBottomPanel::top("topbar")
            .frame(
                Frame::none()
                    .fill(p.base)
                    .inner_margin(Margin::symmetric(16.0, 12.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(theme::page_title("Port-Scan"));
                    ui.add_space(2.0);
                    theme::badge(ui, "RS", p.accent);
                    ui.add_space(4.0);
                    ui.label(theme::dim("端口检测 · 网卡抓包 · pcap 分析").color(p.text_faint));

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let label = if self.dark { "🌙 深色" } else { "☀ 浅色" };
                        if theme::pill(ui, label).clicked() {
                            self.dark = !self.dark;
                        }

                        ui.add_space(4.0);
                        if netif::PCAP_ENABLED {
                            theme::badge(ui, "pcap 已启用", p.green);
                        } else {
                            theme::badge(ui, "pcap 未启用", p.text_faint);
                        }

                        if self.iface_running {
                            ui.add_space(4.0);
                            theme::badge(ui, "网卡抓包中", p.red);
                        }
                        if self.capture_enabled {
                            ui.add_space(4.0);
                            theme::badge(ui, "回环监听中", p.green);
                        }
                        if self.scanning {
                            ui.add_space(4.0);
                            theme::badge(ui, "扫描中", p.amber);
                        }
                        if self.local_loading {
                            ui.add_space(4.0);
                            theme::badge(ui, "读取本机端口…", p.amber);
                        }
                    });
                });

                // 顶栏下的一条细线
                ui.add_space(8.0);
                let rect = ui.max_rect();
                ui.painter().hline(
                    rect.x_range(),
                    rect.bottom() + 11.0,
                    Stroke::new(1.0, p.border),
                );
            });

        SidePanel::left("nav")
            .resizable(false)
            .exact_width(214.0)
            .frame(
                Frame::none()
                    .fill(p.sidebar)
                    .inner_margin(Margin::symmetric(12.0, 14.0)),
            )
            .show(ctx, |ui| {
                let items = [
                    (Tab::Analyze, "📊", "抓包分析"),
                    (Tab::Local, "🖥", "本机端口"),
                    (Tab::Scan, "🌐", "远程扫描"),
                    (Tab::Capture, "📡", "抓包"),
                ];
                for (tab, icon, label) in items {
                    let selected = self.active_tab == tab;
                    if theme::nav_item(ui, selected, icon, label).clicked() && !selected {
                        self.active_tab = tab;
                        // 首次进入本机端口页时启动后台扫描
                        if tab == Tab::Local && self.local_data.is_none() && !self.local_loading {
                            self.start_local_scan();
                        }
                    }
                    ui.add_space(4.0);
                }

                // 侧栏底部的运行概览。
                // bottom_up 布局里「先添加的在最下面」，所以这里的书写顺序是自下而上的：
                // 最终视觉效果自上而下为 运行概览 / 网卡抓包 / 回环监听 / 网卡数 / 分隔线 / 版本。
                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    ui.label(
                        theme::dim(format!("版本 {}", env!("CARGO_PKG_VERSION")))
                            .color(p.text_faint),
                    );
                    ui.add_space(4.0);
                    theme::hairline(ui);
                    ui.horizontal(|ui| {
                        let (color, text) = if self.iface_loading {
                            (p.amber, "读网卡中".to_string())
                        } else if self.ifaces.is_empty() {
                            (p.text_faint, "网卡未读取".to_string())
                        } else {
                            (p.cyan, format!("{} 块网卡", self.ifaces.len()))
                        };
                        theme::dot_label(ui, color, &text);
                    });
                    ui.horizontal(|ui| {
                        theme::dot_label(
                            ui,
                            if self.capture_enabled { p.green } else { p.text_faint },
                            "回环监听",
                        );
                    });
                    ui.horizontal(|ui| {
                        theme::dot_label(
                            ui,
                            if self.iface_running { p.green } else { p.text_faint },
                            "网卡抓包",
                        );
                    });
                    ui.add_space(4.0);
                    ui.label(theme::dim("运行概览").color(p.text_faint));
                });

                // 侧栏右边界线
                let rect = ui.max_rect();
                ui.painter().vline(
                    rect.right() + 12.0,
                    rect.y_range(),
                    Stroke::new(1.0, p.border),
                );
            });

        // 页面内容放进一个纵向滚动区：窗口再小也不会把卡片顶出可视区；
        // 表格自身只做横向滚动，避免出现嵌套的纵向滚动条。
        let stick_to_bottom = self.active_tab == Tab::Capture
            && match self.capture_mode {
                CaptureMode::Iface => self.iface_auto_scroll,
                CaptureMode::Loopback => self.loopback_auto_scroll,
            };

        CentralPanel::default()
            .frame(
                Frame::none()
                    .fill(p.base)
                    .inner_margin(Margin::symmetric(16.0, 14.0)),
            )
            .show(ctx, |ui| {
                ScrollArea::vertical()
                    .id_salt("page_scroll")
                    .auto_shrink([false, false])
                    .stick_to_bottom(stick_to_bottom)
                    .show(ui, |ui| match self.active_tab {
                        Tab::Analyze => self.page_analyze(ui),
                        Tab::Local => self.page_local(ui),
                        Tab::Scan => self.page_scan(ui),
                        Tab::Capture => self.page_capture(ui),
                    });
            });

        // 后台任务未完成时通过 ctx 请求下一帧重绘
        if self.local_loading
            || self.scanning
            || self.capture_enabled
            || self.iface_running
            || self.iface_loading
        {
            ctx.request_repaint();
        }
    }
}

/// 页面级标题行：左侧标题 + 说明，右侧放操作
fn page_header(ui: &mut Ui, title: &str, subtitle: &str, right: impl FnOnce(&mut Ui)) {
    let p = theme::palette(ui);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(theme::page_title(title));
            if !subtitle.is_empty() {
                ui.label(theme::dim(subtitle).color(p.text_faint));
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), right);
    });
    ui.add_space(12.0);
}

/// 错误提示条
fn error_bar(ui: &mut Ui, msg: &str) {
    let p = theme::palette(ui);
    theme::card(ui, |ui| {
        ui.horizontal(|ui| {
            theme::dot_label(ui, p.red, "错误");
            ui.label(theme::dim(msg).color(p.text));
        });
    });
    ui.add_space(8.0);
}

/// 「ip:port」形式的地址
fn addr_str(ip: Option<&str>, port: Option<u16>) -> String {
    match (ip, port) {
        (Some(ip), Some(port)) => format!("{}:{}", ip, port),
        (Some(ip), None) => ip.to_string(),
        _ => "-".to_string(),
    }
}

/// 数据表格的横向滚动容器（纵向由页面滚动区负责）
fn table_area<R>(ui: &mut Ui, id: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    ScrollArea::horizontal()
        .id_salt(id)
        .auto_shrink([false, true])
        .show(ui, add)
        .inner
}

/// 表头行
fn header_row(ui: &mut Ui, cols: &[&str]) {
    let p = theme::palette(ui);
    for c in cols {
        ui.label(theme::col(*c).color(p.text_faint));
    }
    ui.end_row();
}

// ---------------------------------------------------------------------------
// 页面一：抓包分析
// ---------------------------------------------------------------------------

impl App {
    fn page_analyze(&mut self, ui: &mut Ui) {
        let p = theme::palette(ui);
        let subtitle = self
            .loaded_file
            .clone()
            .unwrap_or_else(|| "未打开文件".to_string());

        let mut want_pick = false;
        page_header(ui, "抓包分析", &subtitle, |ui| {
            let has_file = self.packets.is_some();
            if (if has_file {
                theme::ghost_button(ui, "🔄 重新载入")
            } else {
                theme::primary_button(ui, "📂 打开 pcap")
            })
            .clicked()
            {
                want_pick = true;
            }
        });
        if want_pick {
            self.pick_pcap();
        }

        if let Some(err) = self.last_error.clone() {
            error_bar(ui, &err);
        }

        // 未载入文件时的空状态
        if self.packets.is_none() {
            let mut pick_now = false;
            theme::card(ui, |ui| {
                theme::empty_state(
                    ui,
                    "📦",
                    "还没有打开 pcap 文件",
                    "选择一个 pcap 文件后，这里会显示协议统计、TCP 流、握手时间线与包列表",
                );
                ui.vertical_centered(|ui| {
                    if theme::primary_button(ui, "📂 选择文件").clicked() {
                        pick_now = true;
                    }
                });
                ui.add_space(8.0);
            });
            if pick_now {
                self.pick_pcap();
            }
            return;
        }

        // ---- 统计磁贴 ----
        if let Some(stats) = self.stats.clone() {
            ui.horizontal_wrapped(|ui| {
                theme::stat_tile(ui, "总包数", &stats.total_packets.to_string(), p.text);
                theme::stat_tile(ui, "总字节", &human_bytes(stats.total_bytes), p.text);
                theme::stat_tile(
                    ui,
                    "TCP",
                    &format!("{} ({:.0}%)", stats.tcp_packets, stats.tcp_pct()),
                    p.cyan,
                );
                theme::stat_tile(
                    ui,
                    "UDP",
                    &format!("{} ({:.0}%)", stats.udp_packets, stats.udp_pct()),
                    p.purple,
                );
                theme::stat_tile(
                    ui,
                    "HTTP",
                    &format!("{}", stats.http_requests + stats.http_responses),
                    p.accent,
                );
                theme::stat_tile(ui, "三次握手", &stats.tcp_handshakes.to_string(), p.green);
                theme::stat_tile(ui, "TCP 流", &stats.flow_count.to_string(), p.amber);
            });
            ui.add_space(12.0);

            // ---- 标志位 + 流 Top ----
            ui.columns(2, |cols| {
                theme::card_titled(&mut cols[0], "TCP 标志位分布", |ui| {
                    let flags = [
                        ("SYN", stats.tcp_syn, p.cyan),
                        ("SYN+ACK", stats.tcp_synack, p.green),
                        ("ACK", stats.tcp_ack, p.text_dim),
                        ("PSH", stats.tcp_psh, p.accent),
                        ("FIN", stats.tcp_fin, p.amber),
                        ("RST", stats.tcp_rst, p.red),
                    ];
                    Grid::new("flag_grid")
                        .num_columns(3)
                        .spacing([10.0, 6.0])
                        .show(ui, |ui| {
                            for (name, value, color) in flags {
                                theme::badge(ui, name, color);
                                ui.label(theme::mono(value.to_string()).color(p.text));
                                let bar = if stats.tcp_packets > 0 {
                                    value as f32 / stats.tcp_packets as f32
                                } else {
                                    0.0
                                };
                                bar_widget(ui, bar, color);
                                ui.end_row();
                            }
                        });
                });

                theme::card_titled(&mut cols[1], "TCP 流 Top 8（按字节）", |ui| {
                    let Some(streams) = self.streams.clone() else {
                        ui.label(theme::dim("无数据").color(p.text_faint));
                        return;
                    };
                    if streams.is_empty() {
                        ui.label(theme::dim("无数据").color(p.text_faint));
                        return;
                    }
                    let mut list: Vec<&crate::stats::TcpStream> = streams.iter().collect();
                    list.sort_by_key(|s| {
                        std::cmp::Reverse(s.client_bytes as u64 + s.server_bytes as u64)
                    });
                    Grid::new("stream_grid")
                        .num_columns(3)
                        .spacing([10.0, 6.0])
                        .show(ui, |ui| {
                            header_row(ui, &["连接", "标志", "流量"]);
                            for s in list.into_iter().take(8) {
                                ui.label(theme::mono(format!(
                                    "{}:{} → {}:{}",
                                    s.client_ip, s.client_port, s.server_ip, s.server_port
                                )));
                                ui.horizontal(|ui| {
                                    if s.handshake_ok {
                                        theme::badge(ui, "握手✓", p.green);
                                    } else {
                                        theme::badge(ui, "握手✕", p.text_faint);
                                    }
                                    if s.has_http {
                                        theme::badge(ui, "HTTP", p.accent);
                                    }
                                });
                                ui.label(theme::mono(format!(
                                    "↑{} ↓{}",
                                    human_bytes(s.client_bytes as u64),
                                    human_bytes(s.server_bytes as u64)
                                )));
                                ui.end_row();
                            }
                        });
                });
            });
            ui.add_space(12.0);
        }

        // ---- 握手时间线 ----
        if let Some(timelines) = self.timelines.clone() {
            let done = timelines.iter().filter(|t| t.complete).count();
            theme::card_titled(ui, "三次握手时间线", |ui| {
                if timelines.is_empty() {
                    ui.label(theme::dim("该文件里没有捕获到 TCP 握手过程").color(p.text_faint));
                    return;
                }
                ui.horizontal(|ui| {
                    theme::badge(ui, &format!("完成 {}", done), p.green);
                    theme::badge(
                        ui,
                        &format!("未完成 {}", timelines.len() - done),
                        p.amber,
                    );
                });
                ui.add_space(6.0);
                let mut inner = |ui: &mut Ui| {
                    for t in timelines.iter().take(20) {
                        ui.horizontal(|ui| {
                            if t.complete {
                                theme::badge(ui, "完成", p.green);
                            } else {
                                theme::badge(ui, "未完成", p.amber);
                            }
                            ui.label(theme::mono(t.stream_id.clone()));
                        });
                        for ev in &t.events {
                            ui.horizontal(|ui| {
                                ui.add_space(14.0);
                                ui.label(
                                    theme::mono(format!("{:.3}s", ev.timestamp))
                                        .color(p.text_faint),
                                );
                                ui.label(theme::mono(ev.direction.clone()).color(p.text_dim));
                                ui.label(theme::dim(ev.description.clone()).color(p.text_dim));
                                ui.label(theme::mono(ev.flags.clone()).color(p.cyan));
                            });
                        }
                        ui.add_space(6.0);
                    }
                };
                ScrollArea::vertical()
                    .id_salt("timeline_scroll")
                    .max_height(220.0)
                    .show(ui, &mut inner);
            });
            ui.add_space(12.0);
        }

        // ---- 包列表 ----
        let total = self.packets.as_ref().map(|p| p.len()).unwrap_or(0);
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::title("包列表"));
                theme::badge(ui, &format!("共 {} 包", total), p.accent);

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_sized(
                        [220.0, 26.0],
                        TextEdit::singleline(&mut self.analyze_filter)
                            .hint_text("过滤：IP / 端口 / 协议 / HTTP"),
                    );
                    ui.label(theme::dim("显示上限").color(p.text_faint));
                    for (label, value) in [
                        ("全部", 0usize),
                        ("2000", 2000),
                        ("500", 500),
                        ("100", 100),
                    ] {
                        let selected = self.analyze_limit == value;
                        if theme::segment(ui, selected, label).clicked() {
                            self.analyze_limit = value;
                        }
                    }
                });
            });
            ui.add_space(8.0);

            let needle = self.analyze_filter.trim().to_lowercase();
            // 0 表示「全部」，但仍然设一个硬上限
            let limit = if self.analyze_limit == 0 {
                PACKET_ROWS_HARD_CAP
            } else {
                self.analyze_limit.min(PACKET_ROWS_HARD_CAP)
            };
            let Some(packets) = self.packets.clone() else {
                return;
            };

            let mut shown = 0usize;
            table_area(ui, "packet_table", |ui| {
                Grid::new("packet_grid")
                    .num_columns(7)
                    .spacing([14.0, 5.0])
                    .striped(true)
                    .show(ui, |ui| {
                        header_row(
                            ui,
                            &["#", "时间", "源", "目的", "协议", "字节", "摘要"],
                        );
                        for pkt in packets.iter() {
                            if shown >= limit {
                                break;
                            }
                            let summary = packet_summary_text(pkt);
                            let haystack = format!(
                                "{} {} {} {}",
                                addr_str(pkt.src_ip.as_deref(), pkt.src_port),
                                addr_str(pkt.dst_ip.as_deref(), pkt.dst_port),
                                pkt.protocol,
                                summary
                            )
                            .to_lowercase();
                            if !needle.is_empty() && !haystack.contains(&needle) {
                                continue;
                            }
                            shown += 1;

                            ui.label(theme::mono(pkt.seq.to_string()).color(p.text_faint));
                            ui.label(
                                theme::mono(format!("{:.4}", pkt.timestamp)).color(p.text_dim),
                            );
                            ui.label(theme::mono(addr_str(
                                pkt.src_ip.as_deref(),
                                pkt.src_port,
                            )));
                            ui.label(theme::mono(addr_str(
                                pkt.dst_ip.as_deref(),
                                pkt.dst_port,
                            )));
                            theme::badge(ui, &pkt.protocol, p.protocol_color(&pkt.protocol));
                            ui.label(
                                theme::mono(pkt.payload_size.to_string()).color(p.text_dim),
                            );
                            ui.label(theme::dim(summary).color(p.text_dim));
                            ui.end_row();
                        }

                        if shown == 0 {
                            ui.label(theme::dim("没有匹配的包").color(p.text_faint));
                            ui.end_row();
                        }
                    });
            });

            ui.add_space(6.0);
            ui.label(
                theme::dim(format!("显示 {} 行 / 共 {} 包", shown, total)).color(p.text_faint),
            );
        });
    }

    // -----------------------------------------------------------------------
    // 页面二：本机端口
    // -----------------------------------------------------------------------

    fn page_local(&mut self, ui: &mut Ui) {
        let p = theme::palette(ui);
        let total = self.local_data.as_ref().map(|d| d.len()).unwrap_or(0);
        let subtitle = match &self.local_last_updated {
            Some(t) => format!("最近更新 {:.1}s 前", t.elapsed().as_secs_f32()),
            None => "尚未扫描".to_string(),
        };

        page_header(ui, "本机端口", &subtitle, |ui| {
            let btn = if self.local_loading {
                theme::ghost_button(ui, "⏳ 扫描中…")
            } else {
                theme::primary_button(ui, "🔄 刷新")
            };
            if btn.clicked() && !self.local_loading {
                self.start_local_scan();
            }
        });

        if let Some(err) = self.local_error.clone() {
            error_bar(ui, &err);
        }

        // 过滤工具条
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_sized(
                    [260.0, 26.0],
                    TextEdit::singleline(&mut self.local_filter)
                        .hint_text("过滤：端口 / 地址 / 进程名"),
                );

                ui.add_space(6.0);
                for (i, label) in ["全部", "TCP", "UDP"].iter().enumerate() {
                    if theme::segment(ui, self.local_proto == i, label).clicked() {
                        self.local_proto = i;
                    }
                }

                ui.add_space(6.0);
                ui.checkbox(&mut self.local_only_listen, "只看 LISTEN");

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::badge(ui, &format!("共 {} 条", total), p.accent);
                });
            });
        });
        ui.add_space(12.0);

        let Some(entries) = self.local_data.as_ref() else {
            theme::card(ui, |ui| {
                if self.local_loading {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(theme::dim("正在读取本机端口…").color(p.text_dim));
                    });
                    ui.add_space(8.0);
                } else {
                    theme::empty_state(ui, "🖥", "还没有扫描结果", "点右上角「刷新」读取本机端口占用");
                }
            });
            return;
        };

        // 过滤
        let needle = self.local_filter.trim().to_lowercase();
        let rows: Vec<&crate::scanner::PortEntry> = entries
            .iter()
            .filter(|e| {
                if self.local_only_listen && !e.state.eq_ignore_ascii_case("LISTEN") {
                    return false;
                }
                match self.local_proto {
                    1 => e.protocol.eq_ignore_ascii_case("TCP"),
                    2 => e.protocol.eq_ignore_ascii_case("UDP"),
                    _ => true,
                }
            })
            .filter(|e| {
                if needle.is_empty() {
                    return true;
                }
                format!(
                    "{} {}/{} {} {}",
                    e.protocol,
                    e.local_addr,
                    e.local_port,
                    e.state,
                    e.process.clone().unwrap_or_default()
                )
                .to_lowercase()
                .contains(&needle)
            })
            .collect();

        let listen_count = entries
            .iter()
            .filter(|e| e.state.eq_ignore_ascii_case("LISTEN"))
            .count();

        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::title("端口列表"));
                theme::badge(ui, &format!("LISTEN {}", listen_count), p.green);
                theme::badge(ui, &format!("匹配 {}", rows.len()), p.accent);
            });
            ui.add_space(8.0);

            if rows.is_empty() {
                theme::empty_state(ui, "🔍", "没有匹配的端口", "试试放宽过滤条件或切换协议");
                return;
            }

            table_area(ui, "local_table", |ui| {
                Grid::new("local_grid")
                    .num_columns(5)
                    .spacing([14.0, 5.0])
                    .striped(true)
                    .show(ui, |ui| {
                        header_row(ui, &["协议", "本地地址", "远端地址", "状态", "进程"]);
                        for e in &rows {
                            theme::badge(ui, &e.protocol, p.protocol_color(&e.protocol));
                            ui.label(theme::mono(format!("{}:{}", e.local_addr, e.local_port)));
                            let remote = if e.remote_port == 0 {
                                "-".to_string()
                            } else {
                                format!("{}:{}", e.remote_addr, e.remote_port)
                            };
                            ui.label(theme::mono(remote).color(p.text_faint));

                            let listening = e.state.eq_ignore_ascii_case("LISTEN");
                            theme::badge(
                                ui,
                                &e.state,
                                if listening { p.green } else { p.text_dim },
                            );

                            let proc = match (&e.process, e.pid) {
                                (Some(name), Some(pid)) => format!("{} ({})", name, pid),
                                (Some(name), None) => name.clone(),
                                (None, Some(pid)) => format!("pid {}", pid),
                                (None, None) => "-".to_string(),
                            };
                            ui.label(theme::dim(proc).color(p.text));
                            ui.end_row();
                        }
                    });
            });
        });
    }

    // -----------------------------------------------------------------------
    // 页面三：远程扫描
    // -----------------------------------------------------------------------

    fn page_scan(&mut self, ui: &mut Ui) {
        let p = theme::palette(ui);
        let subtitle = if self.scanning {
            "扫描进行中…".to_string()
        } else {
            "支持 IP / 域名，端口写法如 80,443,8000-8100".to_string()
        };

        page_header(ui, "远程扫描", &subtitle, |ui| {
            let btn = if self.scanning {
                theme::ghost_button(ui, "⏳ 扫描中…")
            } else {
                theme::primary_button(ui, "🔍 开始扫描")
            };
            if btn.clicked() && !self.scanning {
                self.start_remote_scan();
            }
        });

        // 目标与参数
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::dim("主机").color(p.text_faint));
                ui.add_sized(
                    [200.0, 26.0],
                    TextEdit::singleline(&mut self.scan_host).hint_text("IP 或域名"),
                );
                ui.add_space(8.0);
                ui.label(theme::dim("端口").color(p.text_faint));
                ui.add_sized(
                    [260.0, 26.0],
                    TextEdit::singleline(&mut self.scan_ports)
                        .hint_text("80,443,8000-8100"),
                );
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(theme::dim("并发").color(p.text_faint));
                ui.add(
                    egui::DragValue::new(&mut self.scan_concurrency)
                        .speed(1.0)
                        .range(1..=1024),
                );
                ui.add_space(12.0);
                ui.label(theme::dim("超时 ms").color(p.text_faint));
                ui.add(
                    egui::DragValue::new(&mut self.scan_timeout_ms)
                        .speed(10.0)
                        .range(10..=60_000),
                );
                ui.add_space(12.0);
                ui.label(
                    theme::dim("（并发越大越快，但可能被目标限流）").color(p.text_faint),
                );
            });
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(theme::dim("端口预设").color(p.text_faint));
                for (label, ports) in [
                    ("常用", "80,443,3306,8080"),
                    ("Web", "80,443,8000,8080,8443"),
                    ("常见服务", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080"),
                    ("1-1024", "1-1024"),
                ] {
                    if theme::pill(ui, label).clicked() {
                        self.scan_ports = ports.to_string();
                    }
                }
            });
        });
        ui.add_space(12.0);

        if let Some(err) = self.scan_error.clone() {
            error_bar(ui, &err);
        }

        let Some(rows) = self.scan_rows.clone() else {
            theme::card(ui, |ui| {
                if self.scanning {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(theme::dim("正在并发探测端口…").color(p.text_dim));
                    });
                    ui.add_space(8.0);
                } else {
                    theme::empty_state(
                        ui,
                        "🌐",
                        "还没有扫描结果",
                        "填好主机与端口后点右上角「开始扫描」",
                    );
                }
            });
            return;
        };

        let open: Vec<&ScanRow> = rows.iter().filter(|r| r.open).collect();
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::title("扫描结果"));
                theme::badge(ui, &format!("开放 {}", open.len()), p.green);
                theme::badge(
                    ui,
                    &format!("关闭 {}", rows.len() - open.len()),
                    p.text_faint,
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        theme::dim(format!("目标 {}:{}", self.scan_host, self.scan_ports))
                            .color(p.text_faint),
                    );
                });
            });
            ui.add_space(8.0);

            if open.is_empty() {
                theme::empty_state(ui, "🔒", "没有发现开放端口", "目标可能开了防火墙，或端口范围不对");
                return;
            }

            table_area(ui, "scan_table", |ui| {
                Grid::new("scan_grid")
                    .num_columns(4)
                    .spacing([14.0, 5.0])
                    .striped(true)
                    .show(ui, |ui| {
                        header_row(ui, &["端口", "服务", "状态", "Banner"]);
                        for r in open.iter() {
                            ui.label(theme::mono(r.port.to_string()));
                            let service = if r.service.is_empty() {
                                "-".to_string()
                            } else {
                                r.service.clone()
                            };
                            ui.label(theme::dim(service).color(p.cyan));
                            theme::badge(ui, "开放", p.green);
                            let banner = r.banner.replace(['\r', '\n'], " ");
                            let banner: String = banner.chars().take(90).collect();
                            ui.label(
                                theme::dim(if banner.trim().is_empty() {
                                    "-".to_string()
                                } else {
                                    banner.trim().to_string()
                                })
                                .color(p.text_dim),
                            );
                            ui.end_row();
                        }
                    });
            });
        });
    }

    // -----------------------------------------------------------------------
    // 页面四：抓包
    // -----------------------------------------------------------------------

    fn page_capture(&mut self, ui: &mut Ui) {
        let p = theme::palette(ui);
        let subtitle = if netif::PCAP_ENABLED {
            "网卡抓包需要 Npcap；回环监听无需任何依赖"
        } else {
            "当前构建未启用 pcap 特性，仅可使用回环监听"
        };

        page_header(ui, "抓包", subtitle, |ui| {
            if !netif::PCAP_ENABLED {
                theme::badge(ui, "网卡抓包不可用", p.amber);
            }
        });

        // 模式切换
        ui.horizontal(|ui| {
            for (mode, label) in [
                (CaptureMode::Iface, "📶 网卡抓包"),
                (CaptureMode::Loopback, "🔁 回环监听"),
            ] {
                let selected = self.capture_mode == mode;
                if theme::tab_chip(ui, selected, label).clicked() && !selected {
                    self.stop_iface_capture();
                    if self.capture_enabled {
                        self.stop_loopback();
                    }
                    self.capture_mode = mode;
                }
            }
        });
        ui.add_space(12.0);

        match self.capture_mode {
            CaptureMode::Iface => self.section_iface(ui),
            CaptureMode::Loopback => self.section_loopback(ui),
        }
    }

    /// 网卡抓包
    fn section_iface(&mut self, ui: &mut Ui) {
        let p = theme::palette(ui);

        // 首次进入时自动枚举网卡
        if self.ifaces.is_empty() && !self.iface_loading {
            self.start_list_ifaces();
        }

        // ---- 网卡选择 ----
        theme::card_titled(ui, "网卡", |ui| {
            ui.horizontal(|ui| {
                let labels: Vec<String> = self.ifaces.iter().map(|f| f.label()).collect();
                let current = labels
                    .get(self.iface_selected)
                    .cloned()
                    .unwrap_or_else(|| {
                        if self.iface_loading {
                            "正在枚举…".to_string()
                        } else {
                            "（未获取到网卡）".to_string()
                        }
                    });

                egui::ComboBox::from_id_salt("iface_pick")
                    .selected_text(current)
                    .width(430.0)
                    .show_ui(ui, |ui| {
                        for (i, label) in labels.iter().enumerate() {
                            ui.selectable_value(&mut self.iface_selected, i, label);
                        }
                    });

                if theme::ghost_button(ui, "🔄 刷新").clicked() && !self.iface_loading {
                    self.start_list_ifaces();
                }
                if self.iface_loading {
                    ui.spinner();
                }
            });

            if let Some(f) = self.ifaces.get(self.iface_selected) {
                ui.add_space(8.0);
                theme::hairline(ui);
                ui.horizontal_wrapped(|ui| {
                    let desc = if f.description.trim().is_empty() {
                        "-".to_string()
                    } else {
                        f.description.clone()
                    };
                    theme::kv(ui, "描述", &desc);
                    ui.add_space(12.0);
                    theme::kv(ui, "MAC", f.mac.as_deref().unwrap_or("-"));
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    let addrs = if f.addresses.is_empty() {
                        "-".to_string()
                    } else {
                        f.addresses.join(", ")
                    };
                    theme::kv(ui, "地址", &addrs);
                    ui.add_space(12.0);
                    ui.label(theme::dim("状态").color(p.text_faint));
                    for part in f.status_text().split(',') {
                        theme::badge(ui, part, p.protocol_color("tcp"));
                    }
                });
                ui.add_space(4.0);
                ui.label(
                    theme::dim(format!("抓包名称：{}", f.name)).color(p.text_faint),
                );
            }
        });
        ui.add_space(12.0);

        // ---- 过滤与输出 ----
        theme::card_titled(ui, "过滤与输出", |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::dim("BPF 过滤").color(p.text_faint));
                ui.add_enabled(
                    !self.iface_running,
                    TextEdit::singleline(&mut self.iface_filter)
                        .hint_text("如 tcp port 80 / host 1.2.3.4")
                        .desired_width(360.0),
                );
                if self.iface_running {
                    theme::badge(ui, "抓包中不可修改", p.amber);
                }
            });
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(theme::dim("快捷").color(p.text_faint));
                for preset in [
                    "tcp port 80",
                    "tcp port 443",
                    "udp port 53",
                    "arp",
                    "icmp",
                    "tcp port 8888",
                ] {
                    if theme::pill(ui, preset).clicked() && !self.iface_running {
                        self.iface_filter = preset.to_string();
                    }
                }
                if theme::pill(ui, "清空").clicked() && !self.iface_running {
                    self.iface_filter.clear();
                }
            });
            ui.add_space(8.0);
            theme::hairline(ui);
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.iface_save, "保存为 pcap");
                ui.add_enabled(
                    self.iface_save && !self.iface_running,
                    TextEdit::singleline(&mut self.iface_save_path)
                        .hint_text("保存路径")
                        .desired_width(240.0),
                );
                ui.label(
                    theme::dim("抓到的包可用「抓包分析」页进一步解析").color(p.text_faint),
                );
            });
        });
        ui.add_space(12.0);

        // ---- 操作 ----
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                if self.iface_running {
                    if theme::danger_button(ui, "⏹ 停止抓包").clicked() {
                        self.stop_iface_capture();
                    }
                } else if theme::primary_button(ui, "▶ 开始抓包").clicked() {
                    self.start_iface_capture();
                }

                ui.add_space(10.0);
                if self.iface_running {
                    let (packets, bytes) = self
                        .iface_handle
                        .as_ref()
                        .map(|h| h.counters())
                        .unwrap_or((0, 0));
                    theme::dot_label(ui, p.green, "抓包中");
                    theme::badge(ui, &format!("{} 包", packets), p.accent);
                    theme::badge(ui, &format!("{}", human_bytes(bytes)), p.accent);
                } else {
                    theme::dot_label(ui, p.text_faint, "已停止");
                }

                if !self.iface_status.is_empty() {
                    ui.add_space(10.0);
                    ui.label(theme::dim(self.iface_status.clone()).color(p.text_dim));
                }
            });

            if let Some(err) = self.iface_error.clone() {
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    theme::dot_label(ui, p.red, "抓包错误");
                    ui.label(theme::dim(err).color(p.red));
                });
            }
        });
        ui.add_space(12.0);

        // ---- 预览 ----
        let needle = self.iface_display_filter.trim().to_lowercase();
        let matched: Vec<&PreviewRow> = self
            .iface_rows
            .iter()
            .filter(|r| {
                if needle.is_empty() {
                    return true;
                }
                format!("{} {} {} {}", r.src, r.dst, r.protocol, r.summary)
                    .to_lowercase()
                    .contains(&needle)
            })
            .collect();
        let shown_start = matched.len().saturating_sub(IFACE_MAX_SHOWN);
        let shown: Vec<&PreviewRow> = matched[shown_start..].to_vec();
        // 「清空」按钮不能在卡片闭包里立刻清空：闭包外还借用着 iface_rows 渲染表格。
        // 先记个标记，等卡片画完再统一处理。
        let mut want_clear = false;

        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::title("实时预览"));
                theme::badge(ui, &format!("匹配 {}", matched.len()), p.accent);
                theme::badge(
                    ui,
                    &format!("缓存 {} / 上限 {}", self.iface_rows.len(), IFACE_MAX_ROWS),
                    p.text_faint,
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::ghost_button(ui, "🗑 清空").clicked() {
                        want_clear = true;
                    }
                    ui.checkbox(&mut self.iface_auto_scroll, "自动滚动");
                    ui.add_sized(
                        [200.0, 26.0],
                        TextEdit::singleline(&mut self.iface_display_filter)
                            .hint_text("显示过滤：IP / 端口 / 协议"),
                    );
                });
            });
            ui.add_space(8.0);

            if shown.is_empty() {
                theme::empty_state(
                    ui,
                    "📡",
                    if self.iface_running {
                        "等待数据…"
                    } else {
                        "还没有抓到数据"
                    },
                    "选择网卡、填好 BPF 过滤后点「开始抓包」",
                );
                return;
            }

            ScrollArea::horizontal()
                .id_salt("iface_preview_scroll")
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    Grid::new("iface_grid")
                        .num_columns(7)
                        .spacing([14.0, 4.0])
                        .striped(true)
                        .show(ui, |ui| {
                            header_row(
                                ui,
                                &["#", "时间", "源", "目的", "协议", "字节", "摘要"],
                            );
                            for r in &shown {
                                ui.label(theme::mono(r.seq.to_string()).color(p.text_faint));
                                ui.label(theme::mono(netif::format_time(r.timestamp)));
                                ui.label(theme::mono(r.src.clone()));
                                ui.label(theme::mono(r.dst.clone()));
                                theme::badge(ui, &r.protocol, p.protocol_color(&r.protocol));
                                ui.label(theme::mono(r.length.to_string()).color(p.text_dim));
                                ui.label(theme::dim(r.summary.clone()).color(p.text_dim));
                                ui.end_row();
                            }
                        });
                });
        });

        if want_clear {
            self.iface_rows.clear();
        }
    }

    /// 回环监听（HTTP 调试）
    fn section_loopback(&mut self, ui: &mut Ui) {
        let p = theme::palette(ui);

        theme::card_titled(ui, "监听设置", |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::dim("监听端口").color(p.text_faint));
                let resp = ui.add_enabled(
                    !self.capture_enabled,
                    TextEdit::singleline(&mut self.capture_port_input).desired_width(80.0),
                );
                if resp.changed() && !self.capture_enabled {
                    let port: u16 = self.capture_port_input.trim().parse().unwrap_or(8888);
                    self.capture_engine = CaptureEngine::new(port);
                }

                ui.add_space(8.0);
                if self.capture_enabled {
                    if theme::danger_button(ui, "⏹ 停止监听").clicked() {
                        self.stop_loopback();
                    }
                } else if theme::primary_button(ui, "▶ 开始监听").clicked() {
                    self.start_loopback();
                }

                ui.add_space(10.0);
                if self.capture_enabled {
                    theme::dot_label(ui, p.green, "正在监听");
                    theme::badge(
                        ui,
                        &format!("{} 包", self.capture_engine.captured_count()),
                        p.accent,
                    );
                    theme::badge(ui, &format!("{} HTTP", self.capture_http_count), p.accent);
                } else {
                    theme::dot_label(ui, p.text_faint, "已停止");
                }
            });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                theme::badge(
                    ui,
                    &format!("http://127.0.0.1:{}", self.capture_engine.port()),
                    p.cyan,
                );
                ui.label(
                    theme::dim("在浏览器或 curl 里访问上面的地址，下方就会实时出现 HTTP 请求/响应")
                        .color(p.text_faint),
                );
            });
        });
        ui.add_space(12.0);

        // 日志区
        let total = self.capture_logs.len();
        let start = total.saturating_sub(LOOPBACK_MAX_SHOWN);
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::title("实时日志"));
                theme::badge(ui, &format!("{} 条", total), p.accent);
                theme::badge(ui, &format!("显示最后 {}", LOOPBACK_MAX_SHOWN), p.text_faint);

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::ghost_button(ui, "🗑 清空").clicked() {
                        self.capture_logs.clear();
                        self.capture_http_count = 0;
                    }
                    ui.checkbox(&mut self.loopback_auto_scroll, "自动滚动");
                });
            });
            ui.add_space(8.0);

            if total == 0 {
                theme::empty_state(
                    ui,
                    "🔁",
                    if self.capture_enabled {
                        "等待请求…"
                    } else {
                        "还没有日志"
                    },
                    "点「开始监听」后访问监听地址即可产生记录",
                );
                return;
            }

            for line in &self.capture_logs[start..] {
                let color = if line.contains("HTTP请求") {
                    p.accent
                } else if line.contains("HTTP响应") {
                    p.amber
                } else if line.contains("[状态]") {
                    p.text_faint
                } else {
                    p.text_dim
                };
                ui.label(theme::mono(line.clone()).color(color));
            }
        });
    }
}

/// 包列表里的一行摘要文本
fn packet_summary_text(p: &crate::parser::ParsedPacket) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(flags) = &p.tcp_flags {
        if !flags.is_empty() {
            parts.push(flags.clone());
        }
    }
    if let Some(h) = &p.http {
        if h.method == "RESPONSE" {
            parts.push(format!("HTTP {}", h.status.clone().unwrap_or_default()));
        } else {
            parts.push(format!("HTTP {} {}", h.method, h.path));
        }
    }
    if !p.src_mac.is_empty() && p.src_ip.is_none() {
        parts.push(format!("{} → {}", p.src_mac, p.dst_mac));
    }
    parts.join(" · ")
}

/// 字节数的可读形式
fn human_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// 细长的比例条，用于标志位分布
fn bar_widget(ui: &mut Ui, ratio: f32, color: Color32) {
    let p = theme::palette(ui);
    let width = 120.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 8.0), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, egui::Rounding::same(4.0), p.elevated);
    let filled = (ratio.clamp(0.0, 1.0) * width).max(2.0);
    painter.rect_filled(
        egui::Rect::from_min_size(rect.min, egui::vec2(filled, rect.height())),
        egui::Rounding::same(4.0),
        color,
    );
}

impl Drop for App {
    fn drop(&mut self) {
        // 关窗时顺手停掉仍在运行的抓包线程
        if self.iface_running {
            self.stop_iface_capture();
        }
        self.capture_engine.stop();
    }
}
