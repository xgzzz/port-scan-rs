//! GUI 模块：基于 egui/eframe 的 Windows 桌面应用
//! 使用纯 Rust 原生窗口，编译为单个 .exe，无外部运行时依赖

use eframe::NativeOptions;
use std::process::ExitCode;

mod app;
pub mod capture_engine;
pub mod theme;

/// 嵌入中文字体：文泉驿微米黑（Apache-2.0，可自由再分发），解决 GUI 中文乱码
const CN_FONT_BYTES: &[u8] = include_bytes!("../../assets/fonts/wqy-microhei.ttc");

/// 双击控制台程序（`port-scan-rs.exe`）时，系统会自动开一个控制台黑窗口；
/// 这里把它隐藏掉，只留下 GUI 窗口。
///
/// 只在“这个控制台只属于我们自己”时才动手，避免把用户正开着的终端窗口一起隐藏。
/// 专用的 `port-scan-rs-gui.exe` 是 Windows 子系统程序，本来就没有控制台，无需调用。
#[cfg(windows)]
pub fn hide_console_if_owned() {
    use windows::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};
    use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};

    unsafe {
        let mut pids = [0u32; 16];
        let attached = GetConsoleProcessList(&mut pids);
        // attached == 1：控制台是随本进程创建的（双击场景）
        // attached > 1：父 shell（cmd/PowerShell）也附着在上面，不能隐藏
        if attached == 1 {
            let hwnd = GetConsoleWindow();
            if !hwnd.is_invalid() {
                let _ = ShowWindow(hwnd, SW_HIDE);
            }
        }
    }
}

#[cfg(not(windows))]
pub fn hide_console_if_owned() {}

pub fn run_gui() -> ExitCode {
    let options = NativeOptions {
        viewport: egui::viewport::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([980.0, 640.0])
            .with_title("Port-Scan-GUI"),
        ..Default::default()
    };

    eframe::run_native(
        "port-scan-gui",
        options,
        Box::new(|cc| {
            // 加载中文字体
            let font_data = egui::epaint::text::FontData::from_owned(CN_FONT_BYTES.to_vec());
            let mut font_defs = egui::epaint::text::FontDefinitions::default();
            font_defs.font_data.insert("CN".to_owned(), font_data);
            font_defs
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .push("CN".into());
            font_defs
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("CN".into());

            // emoji 由 egui 自带的 NotoEmoji / emoji-icon-font 回退渲染。
            // 注意：文案里不要出现「变体选择符 U+FE0F」——它没有独立字形，会被渲染成
            // 一个缺字形方框，看起来就像乱码。写 emoji 时只写基础码位即可
            // （例如桌面电脑只写 U+1F5A5，后面不要再跟 U+FE0F）。
            cc.egui_ctx.set_fonts(font_defs);

            Ok(Box::new(app::App::default()))
        }),
    )
    .map(|_| ExitCode::SUCCESS)
    .unwrap_or(ExitCode::FAILURE)
}
