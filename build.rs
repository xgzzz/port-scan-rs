//! 构建脚本：Windows + pcap 特性时，把 `wpcap.dll` 的静态导入改成「延迟加载」。
//!
//! 背景：pcap crate 在 Windows 上写死了 `#[link(name = "wpcap")]`，属于静态导入。
//! 若目标机器没装 Npcap，进程会在 main 之前就加载失败并直接退出（0xC0000135），
//! 用户只能看到一个静默崩溃，拿不到任何提示。
//!
//! 改成延迟加载后：
//! - 没装 Npcap 的机器也能正常启动，`local` / `scan` / `analyze` 等不依赖抓包的功能照常可用；
//! - 只有真正调用抓包时，才会由 `capture::netif::pcap_runtime_ready()` 给出安装引导。

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let pcap_enabled = std::env::var_os("CARGO_FEATURE_PCAP").is_some();

    if pcap_enabled && target_os == "windows" {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
        // MSVC 的延迟加载辅助库
        println!("cargo:rustc-link-lib=delayimp");
    }
}
