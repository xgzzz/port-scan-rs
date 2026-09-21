//! 仅 GUI 的可执行目标。
//!
//! 声明为 Windows 子系统（GUI 子系统），因此双击时不会像控制台程序那样
//! 附带一个黑色的命令行窗口，也不会有一闪而过的闪烁。
//!
//! CLI 功能仍然由 `port-scan-rs.exe` 提供。

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    port_scan_rs::gui::run_gui()
}
