use crate::table::render_table;
use anyhow::Result;
use colored::*;
use std::process::Command;

/// 端口条目
#[derive(serde::Serialize)]
pub struct PortEntry {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

/// 远程扫描结果
#[derive(serde::Serialize)]
pub struct ScanResult {
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
    pub banner: Option<String>,
}

/// 扫描本机端口
pub fn scan_local_ports() -> Result<Vec<PortEntry>> {
    let mut entries = Vec::new();
    #[cfg(target_os = "windows")]
    {
        entries.extend(scan_windows()?);
    }
    #[cfg(not(target_os = "windows"))]
    {
        entries.extend(scan_unix()?);
    }
    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    Ok(entries)
}

#[cfg(target_os = "windows")]
fn scan_windows() -> Result<Vec<PortEntry>> {
    // 使用 PowerShell 的 Get-NetTCPConnection / Get-NetUDPEndpoint 获取端口。
    // 输出字段顺序固定：协议|本地地址|本地端口|状态|远端地址|远端端口|PID
    let script = r#"
$out = @()
$out += Get-NetTCPConnection -State All -ErrorAction SilentlyContinue | ForEach-Object {
    "{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f 'TCP', $_.LocalAddress, $_.LocalPort, $_.State.ToString(), $_.RemoteAddress, $_.RemotePort, $_.OwningProcess
}
$out += Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
    "{0}|{1}|{2}|LISTEN|{3}|{4}|{5}" -f 'UDP', $_.LocalAddress, $_.LocalPort, '-', 0, $_.OwningProcess
}
$out | Out-String
"#;
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map_err(|e| anyhow::anyhow!("调用 PowerShell 失败: {}", e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let mut entries: Vec<PortEntry> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 7 {
            continue;
        }
        let state = parts[3].trim().to_string();
        // 监听/未连接状态下远端地址没有意义，统一显示为 "-"
        let (remote_addr, remote_port) = if state.eq_ignore_ascii_case("listen") {
            ("-".to_string(), 0)
        } else {
            (
                wildcard_to_star(parts[4].trim()),
                parts[5].trim().parse::<u16>().unwrap_or(0),
            )
        };
        entries.push(PortEntry {
            protocol: parts[0].trim().to_string(),
            local_addr: wildcard_to_star(parts[1].trim()),
            local_port: parts[2].trim().parse().unwrap_or(0),
            remote_addr,
            remote_port,
            state,
            // PID 直接由 PowerShell 给出，进程名稍后由 tasklist 填充
            pid: parts[6].trim().parse::<u32>().ok(),
            process: None,
        });
    }

    fill_process_names(&mut entries);
    Ok(entries)
}

/// 把 0.0.0.0 / :: 这类通配地址显示成 *
#[cfg(target_os = "windows")]
fn wildcard_to_star(addr: &str) -> String {
    match addr {
        "0.0.0.0" | "::" | "*" => "*".to_string(),
        other => other.to_string(),
    }
}

/// 为条目填充进程名（PID -> 映像名）
#[cfg(target_os = "windows")]
fn fill_process_names(entries: &mut [PortEntry]) {
    let pid_to_name = match Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    {
        Ok(o) => parse_tasklist_csv(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => return,
    };
    for e in entries.iter_mut() {
        if let Some(pid) = e.pid {
            e.process = pid_to_name.get(&pid).cloned();
        }
    }
}

/// 解析 `tasklist /FO CSV /NH` 的输出行：`"chrome.exe","1234","Console","1","100,000 K"`
#[cfg(target_os = "windows")]
fn parse_tasklist_csv(text: &str) -> std::collections::HashMap<u32, String> {
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let mut fields = line.split("\",\"");
        let name = match fields.next() {
            Some(f) => f.trim_matches(|c| c == '"' || c == ' ').to_string(),
            None => continue,
        };
        let pid = match fields
            .next()
            .and_then(|f| f.trim_matches('"').trim().parse::<u32>().ok())
        {
            Some(p) => p,
            None => continue,
        };
        if !name.is_empty() {
            map.insert(pid, name);
        }
    }
    map
}

#[cfg(not(target_os = "windows"))]
fn scan_unix() -> Result<Vec<PortEntry>> {
    use std::fs;
    let mut entries = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let local = f[1];
            let sp = local.rfind(':').unwrap();
            let addr = hex_to_ipv4(&local[..sp]);
            let port = u16::from_str_radix(&local[sp + 1..], 16).unwrap_or(0);
            let st = match f[3] {
                "01" => "ESTABLISHED",
                "0A" => "LISTEN",
                "06" => "TIME_WAIT",
                _ => f[3],
            };
            entries.push(PortEntry {
                protocol: "TCP".into(),
                local_addr: addr,
                local_port: port,
                remote_addr: "-".into(),
                remote_port: 0,
                state: st.to_string(),
                pid: None,
                process: None,
            });
        }
    }
    if let Ok(content) = fs::read_to_string("/proc/net/udp") {
        for line in content.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let local = f[1];
            let sp = local.rfind(':').unwrap();
            let addr = hex_to_ipv4(&local[..sp]);
            let port = u16::from_str_radix(&local[sp + 1..], 16).unwrap_or(0);
            entries.push(PortEntry {
                protocol: "UDP".into(),
                local_addr: addr,
                local_port: port,
                remote_addr: "-".into(),
                remote_port: 0,
                state: "UNCONN".into(),
                pid: None,
                process: None,
            });
        }
    }
    Ok(entries)
}

#[cfg(not(target_os = "windows"))]
fn hex_to_ipv4(hex_str: &str) -> String {
    let b = u32::from_str_radix(hex_str, 16).unwrap_or(0);
    if b == 0 {
        "0.0.0.0".into()
    } else {
        format!(
            "{}.{}.{}.{}",
            (b >> 24) & 0xFF,
            (b >> 16) & 0xFF,
            (b >> 8) & 0xFF,
            b & 0xFF
        )
    }
}

/// 显示本地端口
pub fn scan_local(
    listening: bool,
    process: Option<String>,
    pid: Option<u32>,
    json: bool,
) -> Result<()> {
    let entries = scan_local_ports()?;
    let filtered: Vec<&PortEntry> = entries
        .iter()
        .filter(|e| {
            if listening && e.state != "LISTEN" {
                return false;
            }
            if let Some(pf) = &process {
                if !e.process
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&pf.to_lowercase())
                {
                    return false;
                }
            }
            if let Some(p) = pid {
                if e.pid != Some(p) {
                    return false;
                }
            }
            true
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }

    if filtered.is_empty() {
        println!("{}", "(无匹配的端口)".yellow());
        return Ok(());
    }

    let header = vec![
        "协议".to_string(),
        "本地地址".to_string(),
        "状态".to_string(),
        "进程".to_string(),
    ];
    let rows: Vec<Vec<String>> = filtered
        .iter()
        .map(|e| {
            vec![
                e.protocol.clone(),
                format!("{}:{}", e.local_addr, e.local_port),
                e.state.clone(),
                match (&e.process, e.pid) {
                    (Some(name), Some(pid)) => format!("{} ({})", name, pid),
                    (Some(name), None) => name.clone(),
                    (None, Some(pid)) => format!("pid {}", pid),
                    (None, None) => "-".to_string(),
                },
            ]
        })
        .collect();

    println!(
        "\n=== 本机端口 ({} 条, 已过滤) ===",
        filtered.len()
    );
    println!("{}", render_table(&header, &rows));
    Ok(())
}

/// 解析端口范围字符串 "80,443,8080-8090"
pub fn parse_port_range(spec: &str) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("无效端口: {}", a))?;
            let hi: u16 = b
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("无效端口: {}", b))?;
            if lo > hi {
                return Err(anyhow::anyhow!("无效范围: {}-{}", a, b));
            }
            for p in lo..=hi {
                out.push(p);
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| anyhow::anyhow!("无效端口: {}", part))?;
            out.push(p);
        }
    }
    Ok(out)
}

/// 同步扫描远程主机（供 GUI 调用）
pub fn scan_remote_inner_sync(
    host: &str,
    ports_spec: &str,
    concurrency: usize,
    timeout_ms: u64,
) -> anyhow::Result<Vec<ScanResult>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let ports = parse_port_range(ports_spec)?;
        let results = scan_remote_inner(host, &ports, concurrency, timeout_ms).await?;
        Ok(results)
    })
}

/// 扫描远程主机端口
pub async fn scan_remote(
    host: &str,
    ports_spec: &str,
    concurrency: usize,
    timeout_ms: u64,
) -> Result<()> {
    let ports = parse_port_range(ports_spec)?;
    let results = scan_remote_inner(host, &ports, concurrency, timeout_ms).await?;
    display_scan(host, &results)?;
    Ok(())
}

/// 解析主机为单个 IP。域名只解析一次，避免每个端口都做一次 DNS 查询。
async fn resolve_host(host: &str) -> Result<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    tokio::net::lookup_host((host, 0))
        .await?
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| anyhow::anyhow!("无法解析主机名: {}", host))
}

async fn scan_remote_inner(
    host: &str,
    ports: &[u16],
    concurrency: usize,
    timeout_ms: u64,
) -> Result<Vec<ScanResult>> {
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let ip = resolve_host(host).await?;

    // 用 JoinSet 真正并发执行（之前是逐个 await，实际串行、并发参数无效）。
    // 先申请信号量再派生任务，既让同时在飞的连接数不超过 concurrency，
    // 也避免一次性创建海量任务。
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();

    for &port in ports {
        let permit = std::sync::Arc::clone(&sem)
            .acquire_owned()
            .await
            .map_err(|e| anyhow::anyhow!("获取并发令牌失败: {}", e))?;
        tasks.spawn(async move {
            let _permit = permit;
            scan_single(std::net::SocketAddr::new(ip, port), port, timeout).await
        });
    }

    let mut results = Vec::with_capacity(ports.len());
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(r) => results.push(r),
            Err(e) => return Err(anyhow::anyhow!("扫描任务异常退出: {}", e)),
        }
    }
    results.sort_by_key(|r| r.port);
    Ok(results)
}

async fn scan_single(
    addr: std::net::SocketAddr,
    port: u16,
    timeout: std::time::Duration,
) -> ScanResult {
    let connect_result = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await;
    let (open, banner) = match connect_result {
        Ok(Ok(stream)) => (true, try_grab_banner(stream, timeout).await),
        _ => (false, None),
    };

    ScanResult {
        port,
        open,
        service: known_service(port).map(|s| s.to_string()),
        banner,
    }
}

async fn try_grab_banner(
    stream: tokio::net::TcpStream,
    timeout: std::time::Duration,
) -> Option<String> {
    use tokio::io::AsyncWriteExt;
    let mut stream = stream;
    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 256];
    let result = tokio::time::timeout(timeout, async {
        let n = stream.read(&mut buf).await.ok()?;
        Some(String::from_utf8_lossy(&buf[..n]).to_string())
    })
    .await;
    match result {
        Ok(Some(s)) if !s.is_empty() => Some(s.chars().take(80).collect()),
        _ => None,
    }
}

fn known_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 => Some("https"),
        465 => Some("smtps"),
        587 => Some("submission"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        3306 => Some("mysql"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        9090 => Some("zookeeper"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

fn display_scan(host: &str, results: &[ScanResult]) -> Result<()> {
    let open: Vec<&ScanResult> = results.iter().filter(|r| r.open).collect();
    let closed = results.len() - open.len();
    println!(
        "\n=== {} 扫描 {} 个端口，开放 {} 个 ===",
        host.cyan(),
        results.len(),
        open.len()
    );
    if open.is_empty() {
        println!("(未发现开放端口)");
    } else {
        let header = vec![
            "端口".to_string(),
            "服务".to_string(),
            "Banner".to_string(),
        ];
        let rows: Vec<Vec<String>> = open
            .iter()
            .map(|r| {
                vec![
                    r.port.to_string(),
                    r.service.clone().unwrap_or_else(|| "-".into()),
                    r.banner.clone().unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        println!("{}", render_table(&header, &rows));
    }
    println!("(跳过 {} 个关闭/过滤端口)", closed);
    Ok(())
}
