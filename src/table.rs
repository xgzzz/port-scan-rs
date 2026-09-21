//! 终端表格渲染
//!
//! 按字符的显示宽度（中文算 2 列）对齐，供 CLI 各个子命令复用。

use unicode_width::UnicodeWidthStr;

/// 渲染终端表格，返回完整的多行字符串
pub fn render_table(header: &[String], rows: &[Vec<String>]) -> String {
    let col_count = header.len();

    // 先按显示宽度算出每列宽度
    let mut widths: Vec<usize> = header.iter().map(|h| h.width()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < col_count {
                widths[i] = widths[i].max(cell.width());
            }
        }
    }

    let sep = format!(
        "+{}+",
        widths
            .iter()
            .map(|w| "-".repeat(w + 2))
            .collect::<Vec<_>>()
            .join("+")
    );

    let mut out = String::new();
    out.push_str(&sep);
    out.push('\n');
    out.push_str(&render_row(header, &widths));
    out.push('\n');
    out.push_str(&sep);
    out.push('\n');
    for row in rows {
        out.push_str(&render_row(row, &widths));
        out.push('\n');
    }
    out.push_str(&sep);
    out
}

/// 渲染一行：每格左右各留一个空格，不足的按显示宽度右侧补齐
fn render_row(cells: &[String], widths: &[usize]) -> String {
    let mut line = String::from("|");
    for (i, w) in widths.iter().enumerate() {
        let cell = cells.get(i).map(|s| s.as_str()).unwrap_or("");
        line.push(' ');
        line.push_str(cell);
        line.push_str(&" ".repeat(w.saturating_sub(cell.width())));
        line.push_str(" |");
    }
    line
}
