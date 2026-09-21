//! port-scan-rs 的库入口。
//!
//! 同一套模块供两个可执行目标共用：
//!
//! - `port-scan-rs.exe`：带控制台的 CLI；无参数运行时也会启动 GUI（此时会隐藏
//!   系统自动开出的控制台黑窗口）
//! - `port-scan-rs-gui.exe`：Windows 子系统目标，双击只弹 GUI，完全没有控制台窗口

pub mod capture;
pub mod gui;
pub mod parser;
pub mod scanner;
pub mod stats;
pub mod table;
