//! 统一的视觉样式：配色、间距与可复用的界面组件。
//!
//! egui 默认那套样式偏灰、偏密，直接堆控件会显得老旧。这里把它换成一个
//! 更现代的「控制台工具」观感：
//!
//! - 深色底 + 卡片化分区，用一层细边框和圆角区分层次；
//! - 强调色（靛蓝）只用在主操作和选中态上，避免到处都花；
//! - 状态一律用「彩色圆点 / 徽章」表达，而不是只写一段文字；
//! - 地址、端口、时间这类数据用等宽字体，便于逐行扫读；
//! - 间距放开一些，控件高度统一，行高一致。

use egui::{
    Align2, Button, Color32, Context, FontId, Frame, Margin, Rect, Response, RichText, Rounding,
    Sense, Stroke, Ui, Vec2,
};

// ---------------------------------------------------------------------------
// 配色
// ---------------------------------------------------------------------------

/// 十六进制转 Color32
const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb(
        ((hex >> 16) & 0xFF) as u8,
        ((hex >> 8) & 0xFF) as u8,
        (hex & 0xFF) as u8,
    )
}

/// 一套配色（深色 / 浅色各一份）
#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    /// 窗口底色
    pub base: Color32,
    /// 侧边栏 / 顶栏底色
    pub sidebar: Color32,
    /// 卡片底色
    pub card: Color32,
    /// 输入框、次级按钮底色
    pub elevated: Color32,
    /// 悬浮态底色
    pub hover: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_dim: Color32,
    pub text_faint: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub on_accent: Color32,
    pub green: Color32,
    pub cyan: Color32,
    pub amber: Color32,
    pub red: Color32,
    pub purple: Color32,
}

impl Palette {
    pub fn dark() -> Self {
        Self {
            dark: true,
            base: rgb(0x15171C),
            sidebar: rgb(0x1A1D24),
            card: rgb(0x1F232B),
            elevated: rgb(0x262B34),
            hover: rgb(0x2E343F),
            border: rgb(0x2E343E),
            text: rgb(0xE8EAEE),
            text_dim: rgb(0xA3ABB9),
            text_faint: rgb(0x6F7889),
            accent: rgb(0x7C9CFF),
            accent_soft: rgb(0x2B3552),
            on_accent: rgb(0x10131A),
            green: rgb(0x46D19B),
            cyan: rgb(0x4CC9F0),
            amber: rgb(0xF2B544),
            red: rgb(0xFF6B6B),
            purple: rgb(0xB98CFF),
        }
    }

    pub fn light() -> Self {
        Self {
            dark: false,
            base: rgb(0xF3F5F9),
            sidebar: rgb(0xFFFFFF),
            card: rgb(0xFFFFFF),
            elevated: rgb(0xEDF0F6),
            hover: rgb(0xE2E7F0),
            border: rgb(0xDCE1EA),
            text: rgb(0x1E2430),
            text_dim: rgb(0x5B6473),
            text_faint: rgb(0x8A93A3),
            accent: rgb(0x3B6BE0),
            accent_soft: rgb(0xDCE5FB),
            on_accent: rgb(0xFFFFFF),
            green: rgb(0x17945F),
            cyan: rgb(0x0E86B0),
            amber: rgb(0xA9700A),
            red: rgb(0xD64545),
            purple: rgb(0x7A4FD1),
        }
    }

    /// 协议 -> 强调色，用于徽章
    pub fn protocol_color(&self, protocol: &str) -> Color32 {
        let p = protocol.to_ascii_lowercase();
        if p.contains("http") {
            self.accent
        } else if p.starts_with("tcp") {
            self.cyan
        } else if p.starts_with("udp") {
            self.purple
        } else if p.starts_with("arp") {
            self.amber
        } else if p.starts_with("icmp") {
            self.green
        } else if p.starts_with("ipv6") || p.starts_with("ip") {
            self.text_dim
        } else {
            self.text_faint
        }
    }

    /// 把颜色调成很淡的背景色（徽章底）
    pub fn soft(color: Color32) -> Color32 {
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 42)
    }
}

// ---------------------------------------------------------------------------
// 应用样式
// ---------------------------------------------------------------------------

fn palette_id() -> egui::Id {
    egui::Id::new("port_scan_rs_palette")
}

/// 把主题写进 `ctx`，同时把当前配色存进 `ctx.data` 供组件读取
pub fn apply(ctx: &Context, dark: bool) {
    let p = if dark { Palette::dark() } else { Palette::light() };
    ctx.data_mut(|d| d.insert_temp(palette_id(), p));

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals(p);
    style.spacing = spacing();
    style.text_styles = text_styles();
    ctx.set_style(style);
}

/// 取当前配色（组件里用）
pub fn palette(ui: &Ui) -> Palette {
    ui.data(|d| d.get_temp(palette_id()))
        .unwrap_or_else(Palette::dark)
}

/// 取当前配色（面板外层、还没拿到 `Ui` 时用）
pub fn palette_ctx(ctx: &Context) -> Palette {
    ctx.data(|d| d.get_temp(palette_id()))
        .unwrap_or_else(Palette::dark)
}

fn spacing() -> egui::Spacing {
    let mut s = egui::Spacing::default();
    s.item_spacing = Vec2::new(10.0, 9.0);
    s.button_padding = Vec2::new(12.0, 6.0);
    s.window_margin = Margin::same(12.0);
    s.menu_margin = Margin::same(8.0);
    s.indent = 18.0;
    s.interact_size = Vec2::new(36.0, 28.0);
    s.slider_width = 130.0;
    s.combo_width = 220.0;
    s.text_edit_width = 200.0;
    s.icon_width = 16.0;
    s.icon_width_inner = 9.0;
    s.icon_spacing = 7.0;
    s.scroll.bar_width = 9.0;
    s.scroll.bar_inner_margin = 3.0;
    s.scroll.bar_outer_margin = 2.0;
    s
}

fn text_styles() -> std::collections::BTreeMap<egui::TextStyle, FontId> {
    // 注意：`Monospace` 既是 TextStyle 的变体也是 FontFamily 的变体，
    // 两者都用全路径写，避免 glob 导入冲突。
    use egui::{FontFamily, TextStyle};

    [
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Heading,
            FontId::new(21.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        ),
    ]
    .into_iter()
    .collect()
}

fn visuals(p: Palette) -> egui::Visuals {
    let mut v = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    v.dark_mode = p.dark;
    v.override_text_color = Some(p.text);
    v.panel_fill = p.base;
    v.window_fill = p.card;
    v.extreme_bg_color = p.elevated;
    v.faint_bg_color = if p.dark { p.card } else { rgb(0xF7F9FC) };
    v.code_bg_color = p.elevated;
    v.hyperlink_color = p.accent;
    v.warn_fg_color = p.amber;
    v.error_fg_color = p.red;

    v.window_rounding = Rounding::same(12.0);
    v.menu_rounding = Rounding::same(10.0);
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_highlight_topmost = false;

    let shadow_color = if p.dark {
        Color32::from_black_alpha(96)
    } else {
        Color32::from_black_alpha(28)
    };
    let soft_shadow = egui::epaint::Shadow {
        offset: Vec2::new(0.0, 8.0),
        blur: 22.0,
        spread: 0.0,
        color: shadow_color,
    };
    v.window_shadow = soft_shadow;
    v.popup_shadow = egui::epaint::Shadow {
        offset: Vec2::new(0.0, 6.0),
        blur: 16.0,
        spread: 0.0,
        color: shadow_color,
    };

    v.selection = egui::style::Selection {
        bg_fill: p.accent_soft,
        stroke: Stroke::new(1.0, p.accent),
    };

    v.striped = true;
    v.button_frame = true;
    v.collapsing_header_frame = true;
    v.indent_has_left_vline = false;
    v.interact_cursor = Some(egui::CursorIcon::PointingHand);
    v.slider_trailing_fill = true;
    v.clip_rect_margin = 2.0;

    let w = &mut v.widgets;
    w.noninteractive = egui::style::WidgetVisuals {
        bg_fill: p.card,
        weak_bg_fill: p.card,
        bg_stroke: Stroke::new(1.0, p.border),
        rounding: Rounding::same(8.0),
        fg_stroke: Stroke::new(1.0, p.text_dim),
        expansion: 0.0,
    };
    w.inactive = egui::style::WidgetVisuals {
        bg_fill: p.elevated,
        weak_bg_fill: p.elevated,
        bg_stroke: Stroke::new(1.0, p.border),
        rounding: Rounding::same(8.0),
        fg_stroke: Stroke::new(1.0, p.text),
        expansion: 0.0,
    };
    w.hovered = egui::style::WidgetVisuals {
        bg_fill: p.hover,
        weak_bg_fill: p.hover,
        bg_stroke: Stroke::new(1.0, p.accent),
        rounding: Rounding::same(8.0),
        fg_stroke: Stroke::new(1.0, p.text),
        expansion: 1.0,
    };
    w.active = egui::style::WidgetVisuals {
        bg_fill: p.accent_soft,
        weak_bg_fill: p.accent_soft,
        bg_stroke: Stroke::new(1.0, p.accent),
        rounding: Rounding::same(8.0),
        fg_stroke: Stroke::new(1.0, p.text),
        expansion: 0.0,
    };
    w.open = egui::style::WidgetVisuals {
        bg_fill: p.elevated,
        weak_bg_fill: p.elevated,
        bg_stroke: Stroke::new(1.0, p.accent),
        rounding: Rounding::same(8.0),
        fg_stroke: Stroke::new(1.0, p.text),
        expansion: 0.0,
    };

    v
}

// ---------------------------------------------------------------------------
// 文本助手
// ---------------------------------------------------------------------------

/// 卡片标题
pub fn title(text: impl Into<String>) -> RichText {
    RichText::new(text).size(15.0).strong()
}

/// 页面主标题
pub fn page_title(text: impl Into<String>) -> RichText {
    RichText::new(text).size(20.0).strong()
}

/// 次要说明文字
pub fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text).size(12.5)
}

/// 等宽数据（地址、端口、时间…）
pub fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text).font(FontId::monospace(12.5))
}

/// 表头文字
pub fn col(text: impl Into<String>) -> RichText {
    RichText::new(text).size(12.0).strong()
}

// ---------------------------------------------------------------------------
// 容器与组件
// ---------------------------------------------------------------------------

/// 卡片容器：把一组控件包进带边框和圆角的面板
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let p = palette(ui);
    Frame::none()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.border))
        .rounding(Rounding::same(12.0))
        .inner_margin(Margin::symmetric(14.0, 12.0))
        .show(ui, add)
        .inner
}

/// 带标题的卡片
pub fn card_titled<R>(ui: &mut Ui, heading: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    card(ui, |ui| {
        ui.label(title(heading));
        ui.add_space(7.0);
        add(ui)
    })
}

/// 细分割线（比 `ui.separator()` 更收敛）
pub fn hairline(ui: &mut Ui) {
    let p = palette(ui);
    ui.add_space(3.0);
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 1.0), Sense::hover());
    ui.painter().rect_filled(rect, Rounding::ZERO, p.border);
    ui.add_space(3.0);
}

/// 彩色圆点 + 文字，用于状态
pub fn dot_label(ui: &mut Ui, color: Color32, text: &str) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(10.0, 14.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
    ui.label(RichText::new(text).size(13.0).color(color));
}

/// 圆角徽章
pub fn badge(ui: &mut Ui, text: &str, color: Color32) {
    let frame = Frame::none()
        .fill(Palette::soft(color))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(7.0, 2.0));
    let _ = frame.show(ui, |ui| {
        ui.label(RichText::new(text).size(11.5).color(color));
    });
}

/// 键值对（键用淡色小字，值用正文）
pub fn kv(ui: &mut Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        let p = palette(ui);
        ui.label(RichText::new(key).size(12.5).color(p.text_faint));
        ui.label(RichText::new(value).size(12.5).color(p.text));
    });
}

/// 统计磁贴
pub fn stat_tile(ui: &mut Ui, label: &str, value: &str, accent: Color32) {
    let p = palette(ui);
    let frame = Frame::none()
        .fill(p.elevated)
        .stroke(Stroke::new(1.0, p.border))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::symmetric(13.0, 9.0));
    let _ = frame.show(ui, |ui| {
        ui.set_min_width(104.0);
        ui.vertical(|ui| {
            ui.label(RichText::new(label).size(11.5).color(p.text_faint));
            ui.add_space(2.0);
            ui.label(RichText::new(value).size(19.0).strong().color(accent));
        });
    });
}

/// 主操作按钮
pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    let p = palette(ui);
    ui.add(
        Button::new(RichText::new(text).size(13.5).color(p.on_accent))
            .fill(p.accent)
            .stroke(Stroke::NONE)
            .rounding(Rounding::same(8.0))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// 次级按钮
pub fn ghost_button(ui: &mut Ui, text: &str) -> Response {
    let p = palette(ui);
    ui.add(
        Button::new(RichText::new(text).size(13.0).color(p.text))
            .fill(p.elevated)
            .stroke(Stroke::new(1.0, p.border))
            .rounding(Rounding::same(8.0))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// 危险操作按钮（停止抓包等）
pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    let p = palette(ui);
    ui.add(
        Button::new(RichText::new(text).size(13.5).color(p.on_accent))
            .fill(p.red)
            .stroke(Stroke::NONE)
            .rounding(Rounding::same(8.0))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// 小尺寸「胶囊」按钮，用于预设值、过滤器快捷输入
pub fn pill(ui: &mut Ui, text: &str) -> Response {
    let p = palette(ui);
    ui.add(
        Button::new(RichText::new(text).size(12.0).color(p.text_dim))
            .fill(p.elevated)
            .stroke(Stroke::new(1.0, p.border))
            .rounding(Rounding::same(12.0))
            .min_size(Vec2::new(0.0, 24.0)),
    )
}

/// 分段控件中的一个选项
pub fn segment(ui: &mut Ui, selected: bool, text: &str) -> Response {
    let p = palette(ui);
    let (fill, fg, stroke) = if selected {
        (p.accent_soft, p.text, Stroke::new(1.0, p.accent))
    } else {
        (p.elevated, p.text_dim, Stroke::new(1.0, p.border))
    };
    ui.add(
        Button::new(RichText::new(text).size(13.0).color(fg))
            .fill(fill)
            .stroke(stroke)
            .rounding(Rounding::same(8.0))
            .min_size(Vec2::new(0.0, 28.0)),
    )
}

/// 空状态占位
pub fn empty_state(ui: &mut Ui, icon: &str, heading: &str, hint: &str) {
    let p = palette(ui);
    ui.vertical_centered(|ui| {
        ui.add_space(28.0);
        ui.label(RichText::new(icon).size(34.0).color(p.text_faint));
        ui.add_space(6.0);
        ui.label(RichText::new(heading).size(15.0).color(p.text_dim));
        ui.add_space(3.0);
        ui.label(RichText::new(hint).size(12.5).color(p.text_faint));
        ui.add_space(28.0);
    });
}

/// 侧边栏导航项（自绘，保证左对齐 + 选中态左侧强调条）
pub fn nav_item(ui: &mut Ui, selected: bool, icon: &str, label: &str) -> Response {
    let p = palette(ui);
    let width = ui.available_width().max(120.0);
    let height = 38.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, height), Sense::click());
    let hovered = resp.hovered();

    let fill = if selected {
        p.accent_soft
    } else if hovered {
        p.hover
    } else {
        Color32::TRANSPARENT
    };
    let fg = if selected {
        p.text
    } else if hovered {
        p.text
    } else {
        p.text_dim
    };

    let painter = ui.painter();
    painter.rect_filled(rect, Rounding::same(9.0), fill);
    if selected {
        let bar = Rect::from_min_size(
            rect.left_top() + Vec2::new(0.0, 8.0),
            Vec2::new(3.0, height - 16.0),
        );
        painter.rect_filled(bar, Rounding::same(2.0), p.accent);
    }
    painter.text(
        rect.left_center() + Vec2::new(14.0, 0.0),
        Align2::LEFT_CENTER,
        format!("{}  {}", icon, label),
        FontId::proportional(14.0),
        fg,
    );

    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// 可点击的「标签页条」中的一项（比 nav_item 小，用于模式切换）
pub fn tab_chip(ui: &mut Ui, selected: bool, text: &str) -> Response {
    let p = palette(ui);
    let (fill, fg, stroke) = if selected {
        (p.accent, p.on_accent, Stroke::NONE)
    } else {
        (Color32::TRANSPARENT, p.text_dim, Stroke::new(1.0, p.border))
    };
    ui.add(
        Button::new(RichText::new(text).size(13.0).color(fg))
            .fill(fill)
            .stroke(stroke)
            .rounding(Rounding::same(15.0))
            .min_size(Vec2::new(0.0, 28.0)),
    )
}
