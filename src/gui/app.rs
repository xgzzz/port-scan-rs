use egui::{Color32, RichText, TextEdit, Ui};
use egui::{CentralPanel, Grid, ScrollArea, TopBottomPanel};
use crate::capture::netif::{self, IfaceCaptureHandle, IfaceEvent, IfaceInfo, PreviewRow};
use crate::gui::capture_engine::{CaptureEngine, CaptureLog};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::Instant;

/// 网卡抓包预览最多保留的行数
const IFACE_MAX_ROWS: usize = 2000;
/// 预览表格每帧最多渲染的行数
const IFACE_MAX_SHOWN: usize = 500;

/// 后台任务类型
enum TaskResult {
    LocalPorts(Result<Vec<crate::scanner::PortEntry>, String>),
    RemoteScan {
        results: Result<Vec<(u16, String, bool)>, String>,
    },
    Ifaces(Result<Vec<IfaceInfo>, String>),
}

pub struct App {
    // 抓包分析
    pub loaded_file: Option<String>,
    pub packets: Option<std::sync::Arc<Vec<crate::parser::ParsedPacket>>>,
    pub stats: Option<std::sync::Arc<crate::stats::ProtocolStats>>,
    pub streams: Option<std::sync::Arc<Vec<crate::stats::TcpStream>>>,
    pub timelines: Option<std::sync::Arc<Vec<crate::stats::HandshakeTimeline>>>,
    pub last_error: Option<String>,
    pub active_tab: Tab,

    // 远程扫描
    pub scan_host: String,
    pub scan_ports: String,
    pub scan_result: Option<String>,
    pub scanning: bool,

    // 本机端口（缓存 + 后台线程）
    pub local_data: Option<Vec<crate::scanner::PortEntry>>,
    pub local_loading: bool,
    pub local_error: Option<String>,
    pub local_last_updated: Option<Instant>,

    // 抓包（实时）
    pub capture_enabled: bool,
    capture_engine: CaptureEngine,
    capture_logs: Vec<String>,   // 展示用的日志行
    capture_port_input: String,
    capture_http_count: u64,

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
            loaded_file: None,
            packets: None,
            stats: None,
            streams: None,
            timelines: None,
            last_error: None,
            active_tab: Tab::Analyze,
            scan_host: "127.0.0.1".into(),
            scan_ports: "80,443,3306,8080".into(),
            scan_result: None,
            scanning: false,
            local_data: None,
            local_loading: false,
            local_error: None,
            local_last_updated: None,
            capture_enabled: false,
            capture_engine: CaptureEngine::default(),
            capture_logs: Vec::new(),
            capture_port_input: "8888".into(),
            capture_http_count: 0,
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
        self.scan_result = Some("⏳ 扫描中…".into());
        let host = self.scan_host.clone();
        let ports = self.scan_ports.clone();
        let (tx, rx) = mpsc::channel::<TaskResult>();
        self.task_rx = Some(rx);
        std::thread::spawn(move || {
            let result = match crate::scanner::scan_remote_inner_sync(&host, &ports, 20, 500) {
                Ok(results) => {
                    let out: Vec<(u16, String, bool)> = results
                        .into_iter()
                        .map(|r| (r.port, r.service.unwrap_or_default(), r.open))
                        .collect();
                    Ok(out)
                }
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
                            let mut out = String::new();
                            for (port, service, open) in &list {
                                if *open {
                                    out.push_str(&format!("开放 {} {}\n", port, service));
                                }
                            }
                            self.scan_result = Some(if out.is_empty() {
                                "未发现开放端口".to_string()
                            } else {
                                out
                            });
                            self.scanning = false;
                        }
                        Err(e) => {
                            self.scan_result = Some(format!("错误: {}", e));
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

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 每帧非阻塞检查后台任务
        self.poll_tasks();

        TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🔍 Port-Scan-GUI").strong().size(18.0));
                ui.separator();
                if ui
                    .selectable_label(self.active_tab == Tab::Analyze, "📊 抓包分析")
                    .clicked()
                {
                    self.active_tab = Tab::Analyze;
                }
                if ui
                    .selectable_label(self.active_tab == Tab::Local, "🖥️ 本机端口")
                    .clicked()
                {
                    self.active_tab = Tab::Local;
                    // 首次进入且没有缓存时启动后台扫描
                    if self.local_data.is_none() && !self.local_loading {
                        self.start_local_scan();
                    }
                }
                if ui
                    .selectable_label(self.active_tab == Tab::Scan, "🌐 远程扫描")
                    .clicked()
                {
                    self.active_tab = Tab::Scan;
                }
                if ui
                    .selectable_label(self.active_tab == Tab::Capture, "📡 抓包")
                    .clicked()
                {
                    self.active_tab = Tab::Capture;
                }
            });
        });

        CentralPanel::default().show(ctx, |ui| {
            match &mut self.active_tab {
                Tab::Analyze => self.update_analyze(ui),
                Tab::Local => self.update_local(ui),
                Tab::Scan => self.update_scan(ui),
                Tab::Capture => self.update_capture(ui),
            }
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

impl App {
    fn update_analyze(&mut self, ui: &mut Ui) {
        ui.heading("📊 抓包分析");
        ui.separator();

        ui.horizontal(|ui| {
            let mut path = self.loaded_file.clone().unwrap_or_default();
            ui.add_sized(
                egui::vec2(450.0, 20.0),
                TextEdit::singleline(&mut path).desired_width(f32::INFINITY),
            );
            if ui.button("📂 打开 pcap").clicked() {
                if let Some(fp) = rfd::FileDialog::new().pick_file() {
                    path = fp.to_string_lossy().to_string();
                    self.loaded_file = Some(path.clone());
                    self.load_pcap(&path);
                }
            }
            if self.last_error.is_some() {
                ui.label(
                    RichText::new(self.last_error.as_deref().unwrap_or("")).color(Color32::RED),
                );
            }
        });
        ui.separator();

        if let (Some(packets), Some(stats)) = (&self.packets, &self.stats) {
            ui.heading("📈 协议统计");
            Grid::new("stats")
                .num_columns(2)
                .show(ui, |ui| {
                    ui.label("总包数");
                    ui.label(stats.total_packets.to_string());
                    ui.label("总字节");
                    ui.label(stats.total_bytes.to_string());
                    ui.label("TCP 包");
                    ui.label(format!(
                        "{} ({:.1}%)",
                        stats.tcp_packets,
                        stats.tcp_pct()
                    ));
                    ui.label("UDP 包");
                    ui.label(format!(
                        "{} ({:.1}%)",
                        stats.udp_packets,
                        stats.udp_pct()
                    ));
                    ui.label("HTTP 请求");
                    ui.label(stats.http_requests.to_string());
                    ui.label("HTTP 响应");
                    ui.label(stats.http_responses.to_string());
                    ui.label("三次握手");
                    ui.label(stats.tcp_handshakes.to_string());
                    ui.label("流数");
                    ui.label(stats.flow_count.to_string());
                });
            ui.separator();

            ui.heading("🔢 TCP 标志位分布");
            Grid::new("tcp_flags")
                .num_columns(2)
                .show(ui, |ui| {
                    ui.label("SYN");
                    ui.label(stats.tcp_syn.to_string());
                    ui.label("SYN+ACK");
                    ui.label(stats.tcp_synack.to_string());
                    ui.label("ACK");
                    ui.label(stats.tcp_ack.to_string());
                    ui.label("PSH");
                    ui.label(stats.tcp_psh.to_string());
                    ui.label("FIN");
                    ui.label(stats.tcp_fin.to_string());
                    ui.label("RST");
                    ui.label(stats.tcp_rst.to_string());
                });
            ui.separator();

            if let Some(tl) = &self.timelines {
                if !tl.is_empty() {
                    ui.heading("🤝 三次握手时间线");
                    ScrollArea::vertical().show(ui, |ui| {
                        for t in tl.iter().take(20) {
                            let status = if t.complete { "✅" } else { "❌" };
                            ui.label(format!(
                                "{} {} [完成: {}]",
                                status, t.stream_id, t.complete
                            ));
                            for ev in &t.events {
                                ui.label(format!(
                                    "    [{:.3}s] {} {} ({})",
                                    ev.timestamp, ev.direction, ev.description, ev.flags
                                ));
                            }
                        }
                    });
                    ui.separator();
                }
            }

            ui.heading(format!("📦 包列表 ({} 包)", packets.len()));
            let mut rows: Vec<Vec<String>> = Vec::new();
            let limit = 100usize;
            for p in packets.iter().take(limit) {
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
                rows.push(vec![
                    p.seq.to_string(),
                    format!("{:.4}", p.timestamp),
                    p.src_ip.clone().unwrap_or_else(|| "-".into()),
                    p.dst_ip.clone().unwrap_or_else(|| "-".into()),
                    p.src_port.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
                    p.dst_port.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
                    proto,
                    p.payload_size.to_string(),
                    http,
                ]);
            }
            render_table(ui, rows, packets.len() as usize, limit);

            if packets.len() > limit {
                ui.label(format!(
                    "(显示前 {} 条，共 {} 条)",
                    limit,
                    packets.len()
                ));
            }
        } else {
            ui.label("请选择一个 pcap 文件以开始分析");
        }
    }

    fn update_local(&mut self, ui: &mut Ui) {
        ui.heading("🖥️ 本机端口");
        ui.separator();

        ui.horizontal(|ui| {
            let is_disabled = self.local_loading;
            if ui
                .add_enabled(!is_disabled, egui::Button::new("🔄 刷新本机端口"))
                .clicked()
            {
                self.start_local_scan();
            }
            if is_disabled {
                ui.label("⏳ 正在后台扫描…");
            }
            if let Some(t) = &self.local_last_updated {
                ui.label(format!("更新于 {:.1}s 前", t.elapsed().as_secs_f32()));
            }
        });
        ui.separator();

        if let Some(err) = &self.local_error {
            ui.label(RichText::new(err.clone()).color(Color32::RED));
        }

        if let Some(entries) = &self.local_data {
            let filtered: Vec<_> = entries
                .iter()
                .filter(|e| e.state == "LISTEN")
                .take(50)
                .collect();
            let mut rows: Vec<Vec<String>> = Vec::new();
            for e in filtered {
                let proc = e.process.clone().unwrap_or_else(|| "-".into());
                rows.push(vec![
                    e.protocol.clone(),
                    format!("{}:{}", e.local_addr, e.local_port),
                    e.state.clone(),
                    proc,
                ]);
            }
            ui.label(format!(
                "共 {} 个端口，显示前 {} 个 LISTEN",
                entries.len(),
                rows.len()
            ));
            render_table_simple(
                ui,
                &["协议".into(), "本地地址".into(), "状态".into(), "进程".into()],
                &rows,
            );
        } else if self.local_loading {
            ui.label("⏳ 首次扫描中，请稍候…");
        }
    }

    fn update_scan(&mut self, ui: &mut Ui) {
        ui.heading("🌐 远程端口扫描");
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("主机:");
            ui.add_sized(
                egui::vec2(200.0, 20.0),
                TextEdit::singleline(&mut self.scan_host).desired_width(f32::INFINITY),
            );
            ui.label("端口:");
            ui.add_sized(
                egui::vec2(200.0, 20.0),
                TextEdit::singleline(&mut self.scan_ports).desired_width(f32::INFINITY),
            );
            if ui.add_enabled(!self.scanning, egui::Button::new("🔍 扫描")).clicked() {
                self.start_remote_scan();
            }
            if self.scanning {
                ui.label("⏳ 扫描中…");
            }
        });
        ui.separator();

        if let Some(res) = &self.scan_result {
            if !res.starts_with("⏳") {
                ui.heading("📋 扫描结果");
                let res = res.clone();
                ScrollArea::vertical().show(ui, |ui| {
                    ui.label(res);
                });
            }
        }
    }

    /// 抓包页：网卡抓包 / 回环监听 两种模式
    fn update_capture(&mut self, ui: &mut Ui) {
        ui.heading("📡 抓包");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("模式:");
            if ui
                .selectable_label(self.capture_mode == CaptureMode::Iface, "网卡抓包")
                .clicked()
                && self.capture_mode != CaptureMode::Iface
            {
                self.stop_iface_capture();
                self.capture_mode = CaptureMode::Iface;
            }
            if ui
                .selectable_label(
                    self.capture_mode == CaptureMode::Loopback,
                    "回环监听（HTTP 调试）",
                )
                .clicked()
                && self.capture_mode != CaptureMode::Loopback
            {
                self.stop_iface_capture();
                self.capture_mode = CaptureMode::Loopback;
            }
            if !netif::PCAP_ENABLED {
                ui.colored_label(
                    Color32::YELLOW,
                    "（当前编译未启用 pcap 特性，网卡抓包不可用）",
                );
            }
        });
        ui.separator();

        match self.capture_mode {
            CaptureMode::Iface => self.update_capture_iface(ui),
            CaptureMode::Loopback => self.update_capture_loopback(ui),
        }
    }

    /// 网卡抓包：网卡选择 + BPF 过滤 + 实时预览
    fn update_capture_iface(&mut self, ui: &mut Ui) {
        // 首次进入时自动枚举网卡
        if self.ifaces.is_empty() && !self.iface_loading {
            self.start_list_ifaces();
        }

        ui.horizontal(|ui| {
            ui.label("网卡:");
            let current = self
                .ifaces
                .get(self.iface_selected)
                .map(|f| f.label())
                .unwrap_or_else(|| "(请先刷新网卡列表)".to_string());
            egui::ComboBox::from_id_salt("iface_pick")
                .selected_text(current)
                .width(420.0)
                .show_ui(ui, |ui| {
                    for (i, f) in self.ifaces.iter().enumerate() {
                        ui.selectable_value(&mut self.iface_selected, i, f.label());
                    }
                });
            if ui
                .add_enabled(!self.iface_loading, egui::Button::new("🔄 刷新网卡"))
                .clicked()
            {
                self.start_list_ifaces();
            }
            if self.iface_loading {
                ui.label("⏳ 正在枚举网卡…");
            }
        });

        if let Some(f) = self.ifaces.get(self.iface_selected) {
            let desc = if f.description.trim().is_empty() {
                "-"
            } else {
                f.description.as_str()
            };
            let addrs = if f.addresses.is_empty() {
                "-".to_string()
            } else {
                f.addresses.join(", ")
            };
            ui.label(format!(
                "描述: {}    MAC: {}    地址: {}    状态: {}",
                desc,
                f.mac.clone().unwrap_or_else(|| "-".into()),
                addrs,
                f.status_text()
            ));
        }

        ui.horizontal(|ui| {
            ui.label("BPF 过滤:");
            ui.add_enabled(
                !self.iface_running,
                TextEdit::singleline(&mut self.iface_filter)
                    .hint_text("如 tcp port 80 / host 1.2.3.4 / udp")
                    .desired_width(320.0),
            );
        });

        ui.horizontal(|ui| {
            let label = if self.iface_running {
                "⏹ 停止抓包"
            } else {
                "▶ 开始抓包"
            };
            if ui.button(label).clicked() {
                if self.iface_running {
                    self.stop_iface_capture();
                } else {
                    self.start_iface_capture();
                }
            }
            ui.checkbox(&mut self.iface_save, "保存到文件");
            ui.add_enabled(
                self.iface_save && !self.iface_running,
                TextEdit::singleline(&mut self.iface_save_path).desired_width(180.0),
            );
            if self.iface_running {
                let (packets, bytes) = self
                    .iface_handle
                    .as_ref()
                    .map(|h| h.counters())
                    .unwrap_or((0, 0));
                ui.colored_label(
                    Color32::from_rgb(0, 200, 80),
                    format!("● 抓包中  已捕获 {} 包 / {} 字节", packets, bytes),
                );
            } else {
                ui.colored_label(Color32::GRAY, "○ 已停止");
            }
        });

        if !self.iface_status.is_empty() {
            ui.label(format!("状态: {}", self.iface_status));
        }
        if let Some(err) = self.iface_error.clone() {
            ui.colored_label(Color32::RED, err);
        }
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("显示过滤:");
            ui.add_sized(
                egui::vec2(240.0, 20.0),
                TextEdit::singleline(&mut self.iface_display_filter)
                    .hint_text("对已抓到的行做文本匹配")
                    .desired_width(f32::INFINITY),
            );
            ui.checkbox(&mut self.iface_auto_scroll, "自动滚动");
            if ui.button("🗑 清空").clicked() {
                self.iface_rows.clear();
            }
        });

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

        ui.label(format!(
            "预览: 匹配 {} 行 / 共 {} 行（每帧最多渲染 {} 行）",
            matched.len(),
            self.iface_rows.len(),
            IFACE_MAX_SHOWN
        ));

        let start = matched.len().saturating_sub(IFACE_MAX_SHOWN);
        let shown = &matched[start..];
        let auto_scroll = self.iface_auto_scroll;

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(auto_scroll)
            .show(ui, |ui| {
                Grid::new("iface_preview")
                    .num_columns(7)
                    .spacing([10.0, 2.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for h in ["#", "时间", "源", "目的", "协议", "长度", "摘要"] {
                            ui.strong(h);
                        }
                        ui.end_row();
                        if shown.is_empty() {
                            ui.label("等待数据…");
                            ui.end_row();
                        }
                        for r in shown {
                            ui.label(r.seq.to_string());
                            ui.label(netif::format_time(r.timestamp));
                            ui.label(r.src.clone());
                            ui.label(r.dst.clone());
                            ui.label(r.protocol.clone());
                            ui.label(format!("{} B", r.length));
                            ui.label(r.summary.clone());
                            ui.end_row();
                        }
                    });
            });
    }

    /// 回环监听：本地起一个 TCP 端口，实时解析 HTTP 请求/响应
    fn update_capture_loopback(&mut self, ui: &mut Ui) {
        ui.heading("📡 实时抓包（回环监听）");
        ui.separator();

        // 开关行
        ui.horizontal(|ui| {
            ui.label("抓包开关:");
            let running = self.capture_enabled;
            if ui
                .add_sized(
                    egui::vec2(60.0, 20.0),
                    egui::widgets::Checkbox::new(&mut self.capture_enabled, ""),
                )
                .clicked()
            {
                if self.capture_enabled && !running {
                    let port: u16 = self
                        .capture_port_input
                        .parse()
                        .unwrap_or(8888);
                    self.capture_engine = CaptureEngine::new(port);
                    self.capture_engine.start();
                    self.capture_logs.clear();
                    self.capture_http_count = 0;
                } else if running && !self.capture_enabled {
                    self.capture_engine.stop();
                }
            }
            if self.capture_enabled {
                ui.colored_label(Color32::from_rgb(0, 200, 80), "● 正在监听");
                ui.label(format!(
                    "已捕获 {} 包 / {} HTTP",
                    self.capture_engine.captured_count(),
                    self.capture_http_count
                ));
            } else {
                ui.colored_label(Color32::GRAY, "○ 已停止");
            }
        });
        ui.separator();

        // 端口设置行
        ui.horizontal(|ui| {
            ui.label("监听端口:");
            let port_changed = ui
                .add_sized(
                    egui::vec2(80.0, 20.0),
                    TextEdit::singleline(&mut self.capture_port_input).desired_width(80.0),
                )
                .changed();
            let apply_clicked = ui
                .add_enabled(!self.capture_enabled, egui::Button::new("💾 应用"))
                .clicked();
            if apply_clicked || (port_changed && !self.capture_enabled) {
                let port: u16 = self.capture_port_input.parse().unwrap_or(8888);
                self.capture_engine = CaptureEngine::new(port);
            }
            ui.label(format!("当前: 127.0.0.1:{}", self.capture_engine.port()));
        });
        ui.separator();

        // 使用说明
        ui.horizontal(|ui| {
            ui.label("💡 使用方法: 在浏览器或 curl 中访问 http://127.0.0.1:");
            ui.colored_label(Color32::YELLOW, &self.capture_port_input);
            ui.label(", 即可在下方看到实时 HTTP 请求。");
        });

        // 实时日志区
        ui.separator();
        ui.label(format!(
            "📋 实时日志 ({} 条, 显示最后 200 条)",
            self.capture_logs.len()
        ));
        ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if self.capture_logs.is_empty() {
                ui.label("等待数据…");
            } else {
                let start = self.capture_logs.len().saturating_sub(200);
                for line in &self.capture_logs[start..] {
                    let color = if line.contains("HTTP请求") {
                        Color32::from_rgb(80, 160, 255)
                    } else if line.contains("HTTP响应") {
                        Color32::from_rgb(255, 160, 80)
                    } else if line.contains("[状态]") {
                        Color32::GRAY
                    } else {
                        Color32::LIGHT_GRAY
                    };
                    ui.label(RichText::new(line.clone()).color(color));
                }
            }
        });
    }
}

/// 渲染包列表表格
fn render_table(ui: &mut Ui, rows: Vec<Vec<String>>, _total: usize, _limit: usize) {
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
    render_table_simple(ui, &header, &rows);
}

/// 用 Grid 渲染表格
fn render_table_simple(ui: &mut Ui, header: &[String], rows: &[Vec<String>]) {
    let col_count = rows.first().map(|r| r.len()).unwrap_or(header.len());
    let col_count = col_count.max(header.len());
    ScrollArea::vertical().show(ui, |ui| {
        Grid::new("tbl")
            .num_columns(col_count)
            .spacing([8.0, 2.0])
            .show(ui, |ui| {
                for h in header {
                    ui.strong(h.clone());
                }
                ui.end_row();
                for row in rows {
                    for (i, cell) in row.iter().enumerate() {
                        if i < col_count {
                            ui.label(cell.clone());
                        }
                    }
                    ui.end_row();
                }
            });
    });
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
