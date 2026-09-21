//! GUI 模块：基于 egui/eframe 的 Windows 桌面应用
//! 使用纯 Rust 原生窗口，编译为单个 .exe，无外部运行时依赖

use eframe::NativeOptions;
use std::process::ExitCode;

mod app;
pub mod capture_engine;

/// 嵌入幼圆中文字体（~6MB），解决 GUI 中文乱码
const CN_FONT_BYTES: &[u8] = include_bytes!("../../assets/fonts/simyou.ttf");

pub fn run_gui() -> ExitCode {
    let options = NativeOptions {
        viewport: egui::viewport::ViewportBuilder::default()
            .with_inner_size([1100.0, 750.0])
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

            cc.egui_ctx.set_fonts(font_defs);

            Ok(Box::new(app::App::default()))
        }),
    )
    .map(|_| ExitCode::SUCCESS)
    .unwrap_or(ExitCode::FAILURE)
}
