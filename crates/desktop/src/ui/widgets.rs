//! Reusable building blocks. Screens compose these and never style raw
//! egui widgets themselves, so every screen looks and behaves the same.

use eframe::egui::{
    self, Align, Align2, Button, CornerRadius, Frame, Layout, Margin, Response, RichText, Stroke,
    Ui,
};

use zeroize::Zeroizing;

use super::format::short_hash;
use super::icons::Icon;
use super::theme::{self, Tone};

/// A page: title, one-line description, and width-limited content.
pub fn page<R>(
    ui: &mut Ui,
    title: &str,
    subtitle: &str,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> R {
    ui.set_max_width(ui.available_width().min(theme::CONTENT_WIDTH));
    ui.heading(title);
    ui.label(RichText::new(subtitle).color(theme::TEXT_MUTED));
    ui.add_space(theme::SPACE_LG);
    add_contents(ui)
}

/// A bordered surface that groups related content and fills the row.
pub fn card<R>(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    tinted_card(ui, theme::BORDER, add_contents)
}

/// A card whose border draws attention, such as a payment awaiting approval.
pub fn highlighted_card<R>(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    tinted_card(ui, theme::ACCENT_TEXT, add_contents)
}

fn tinted_card<R>(
    ui: &mut Ui,
    border: egui::Color32,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> R {
    let inner = Frame::new()
        .fill(theme::SURFACE)
        .stroke(Stroke::new(theme::LINE_WIDTH, border))
        .corner_radius(CornerRadius::same(theme::RADIUS_LG))
        .inner_margin(Margin::same(theme::CARD_PADDING))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
        .inner;
    ui.add_space(theme::SPACE_MD);
    inner
}

/// The title of a card.
pub fn card_title(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).size(theme::TITLE_SIZE).strong());
}

/// Small muted text: captions, hints, and explanations.
pub fn caption(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .size(theme::SMALL_SIZE)
            .color(theme::TEXT_MUTED),
    );
}

/// A heading above a group of cards.
pub fn section(ui: &mut Ui, title: &str) {
    ui.add_space(theme::SPACE_SM);
    ui.label(
        RichText::new(title.to_uppercase())
            .size(theme::SMALL_SIZE)
            .color(theme::TEXT_MUTED)
            .strong(),
    );
    ui.add_space(theme::SPACE_XS);
}

/// A labelled figure inside its own card, for rows of key numbers.
pub fn stat(ui: &mut Ui, label: &str, value: &str) {
    card(ui, |ui| {
        caption(ui, label);
        ui.label(RichText::new(value).size(theme::TITLE_SIZE + 4.0).strong());
    });
}

/// The main figure of a page, such as the spendable balance.
pub fn display_amount(ui: &mut Ui, amount: &str, unit: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(amount).font(theme::display_font()).strong());
        ui.label(
            RichText::new(unit)
                .size(theme::TITLE_SIZE)
                .color(theme::TEXT_MUTED),
        );
    });
}

/// A label on the left and a value on the right.
pub fn key_value(ui: &mut Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(key).color(theme::TEXT_MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).monospace());
        });
    });
}

/// A form field's label with an optional hint below it.
pub fn field_label(ui: &mut Ui, label: &str, hint: Option<&str>) {
    ui.add_space(theme::SPACE_XS);
    ui.label(RichText::new(label).strong());
    if let Some(hint) = hint {
        caption(ui, hint);
    }
}

/// The one button a view most wants pressed.
pub fn primary_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    ui.scope(|ui| {
        let widgets = &mut ui.visuals_mut().widgets;
        for (state, fill) in [
            (&mut widgets.inactive, theme::ACCENT),
            (&mut widgets.hovered, theme::ACCENT_HOVER),
            (&mut widgets.active, theme::ACCENT_HOVER),
        ] {
            state.weak_bg_fill = fill;
            state.bg_stroke = Stroke::NONE;
        }
        let label = RichText::new(text).color(theme::ON_ACCENT).strong();
        ui.add_enabled(enabled, Button::new(label).min_size(control_size()))
    })
    .inner
}

/// Any other action.
pub fn secondary_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    ui.add_enabled(enabled, Button::new(text).min_size(control_size()))
}

/// A short colored state label, such as "confirmed".
pub fn badge(ui: &mut Ui, text: &str, tone: Tone) {
    Frame::new()
        .fill(tone.fill())
        .corner_radius(CornerRadius::same(theme::RADIUS_SM))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .size(theme::SMALL_SIZE)
                    .color(tone.color())
                    .strong(),
            );
        });
}

/// A full-width message box explaining state or a problem.
pub fn notice(ui: &mut Ui, tone: Tone, text: &str) {
    Frame::new()
        .fill(tone.fill())
        .stroke(Stroke::new(
            theme::LINE_WIDTH,
            tone.color().gamma_multiply(0.5),
        ))
        .corner_radius(CornerRadius::same(theme::RADIUS_LG))
        .inner_margin(Margin::same(theme::CARD_PADDING - 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(text).color(tone.color()));
        });
    ui.add_space(theme::SPACE_MD);
}

/// What to show when a list has no entries yet.
pub fn empty_state(ui: &mut Ui, title: &str, body: &str) {
    card(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(theme::SPACE_SM);
            ui.label(RichText::new(title).strong());
            caption(ui, body);
            ui.add_space(theme::SPACE_SM);
        });
    });
}

/// Monospace text, wrapped, with a button that copies it.
pub fn copyable(ui: &mut Ui, value: &str) {
    ui.horizontal(|ui| {
        if secondary_button(ui, "Copy", true).clicked() {
            ui.ctx().copy_text(value.to_owned());
        }
        ui.add(egui::Label::new(RichText::new(value).monospace()).wrap());
    });
}

/// A shortened identifier; hover shows it in full and clicking copies it.
pub fn hash(ui: &mut Ui, value: &str) {
    let response = ui
        .add(
            egui::Label::new(
                RichText::new(short_hash(value))
                    .monospace()
                    .color(theme::TEXT_MUTED),
            )
            .sense(egui::Sense::click()),
        )
        .on_hover_text(format!("{value}\nClick to copy"));
    if response.clicked() {
        ui.ctx().copy_text(value.to_owned());
    }
}

/// A sidebar entry: icon and label, left-aligned, as wide as the sidebar
/// and one control high. The selected page gets a raised fill, an accent
/// bar, and an accent icon; hovering raises the fill slightly.
pub fn nav_item(ui: &mut Ui, icon: Icon, label: &str, selected: bool) -> Response {
    let size = egui::vec2(ui.available_width(), theme::CONTROL_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, label)
    });
    let painter = ui.painter_at(rect);
    let radius = CornerRadius::same(theme::RADIUS_SM);
    let (fill, text, glyph) = match (selected, response.hovered()) {
        (true, _) => (theme::SURFACE_RAISED, theme::TEXT, theme::ACCENT),
        (false, true) => (theme::SURFACE, theme::TEXT, theme::TEXT),
        (false, false) => (
            egui::Color32::TRANSPARENT,
            theme::TEXT_MUTED,
            theme::TEXT_MUTED,
        ),
    };
    painter.rect_filled(rect, radius, fill);
    if selected {
        let bar = egui::Rect::from_min_size(
            egui::pos2(rect.left(), rect.top() + theme::SPACE_SM),
            egui::vec2(
                theme::SELECTED_BAR_WIDTH,
                rect.height() - 2.0 * theme::SPACE_SM,
            ),
        );
        painter.rect_filled(bar, CornerRadius::same(2), theme::ACCENT);
    }
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(
            rect.left() + theme::SPACE_MD + theme::ICON_SIZE / 2.0,
            rect.center().y,
        ),
        egui::Vec2::splat(theme::ICON_SIZE),
    );
    icon.paint(&painter, icon_rect, glyph);
    painter.text(
        egui::pos2(icon_rect.right() + theme::SPACE_MD, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(theme::BODY_SIZE),
        text,
    );
    response
}

/// Minimum size of a button: content width, comfortable height.
fn control_size() -> egui::Vec2 {
    egui::vec2(0.0, theme::CONTROL_HEIGHT)
}

/// A text input for a secret that keeps no undo history of it. `masked`
/// hides the text; unmasked suits single recovery words being checked.
pub fn secret_input(ui: &mut Ui, value: &mut Zeroizing<String>, id: &str, masked: bool) {
    let mut output = egui::TextEdit::singleline(&mut **value)
        .id_salt(id)
        .password(masked)
        .desired_width(f32::INFINITY)
        .margin(egui::vec2(theme::SPACE_SM, theme::SPACE_SM))
        .show(ui);
    // Do not retain passphrases or seeds in the widget's undo history.
    output.state.clear_undoer();
    output.state.store(ui.ctx(), output.response.id);
}

/// Light modules scanners need around a QR code, per side.
const QR_QUIET_ZONE: usize = 4;

/// The modules of a QR code for `text`, row by row, `true` for dark, with
/// the side length. `None` if the text is too long to encode.
fn qr_modules(text: &str) -> Option<(usize, Vec<bool>)> {
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M).ok()?;
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    // A zero width would make row chunking panic; the library never
    // returns one, but this is drawn every frame.
    Some((code.width(), dark)).filter(|(width, _)| *width > 0)
}

/// A scannable QR code of `text`, dark on light in either theme.
pub fn qr_code(ui: &mut Ui, text: &str) {
    let Some((width, modules)) = qr_modules(text) else {
        caption(ui, "Too long to show as a QR code.");
        return;
    };
    let side = width.saturating_add(QR_QUIET_ZONE.saturating_mul(2));
    // Module counts are at most 177 plus the quiet zone, exact in f32.
    #[allow(clippy::cast_precision_loss)]
    let module = theme::QR_SIZE / side as f32;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(theme::QR_SIZE, theme::QR_SIZE),
        egui::Sense::hover(),
    );
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(theme::RADIUS_SM), theme::QR_LIGHT);
    let offset = |modules: usize| {
        // As above: small module counts convert to f32 exactly.
        #[allow(clippy::cast_precision_loss)]
        let modules = modules.saturating_add(QR_QUIET_ZONE) as f32;
        modules * module
    };
    for (row, line) in modules.chunks(width).enumerate() {
        for (col, _) in line.iter().enumerate().filter(|(_, dark)| **dark) {
            let min = egui::pos2(rect.min.x + offset(col), rect.min.y + offset(row));
            painter.rect_filled(
                egui::Rect::from_min_size(min, egui::vec2(module, module)),
                CornerRadius::ZERO,
                theme::QR_DARK,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_codes_are_square_and_cover_long_addresses() {
        let address = format!("tnull1{}", "q".repeat(150));
        let (width, modules) = qr_modules(&address).unwrap();
        assert_eq!(modules.len(), width * width);
        assert!(modules.iter().any(|dark| *dark) && modules.iter().any(|dark| !*dark));
        assert!(qr_modules(&"x".repeat(5000)).is_none());
    }

    #[test]
    fn qr_codes_differ_for_different_text() {
        assert_ne!(qr_modules("tnull1a"), qr_modules("tnull1b"));
    }

    #[test]
    fn sidebar_items_stack_from_the_top_and_fit_a_small_window() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let height = 580.0;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(760.0, height),
            )),
            ..Default::default()
        };
        let mut rects = Vec::new();
        let _ = ctx.run(input, |ctx| {
            egui::SidePanel::left("nav")
                .exact_width(theme::SIDEBAR_WIDTH)
                .show(ctx, |ui| {
                    for label in ["Overview", "Receive", "Send", "Activity", "Node"] {
                        rects.push(nav_item(ui, Icon::Send, label, label == "Send").rect);
                    }
                });
        });
        let first = rects[0];
        assert!(first.top() < theme::CONTROL_HEIGHT * 2.0, "{first:?}");
        for pair in rects.windows(2) {
            let gap = pair[1].top() - pair[0].bottom();
            assert!((0.0..=theme::SPACE_MD).contains(&gap), "{pair:?}");
        }
        assert!(rects.iter().all(|r| r.bottom() <= height), "{rects:?}");
    }
}
