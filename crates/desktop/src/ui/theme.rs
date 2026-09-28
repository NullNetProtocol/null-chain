//! Design tokens: the only place that names colors, sizes, and spacing.
//!
//! Screens and widgets refer to these tokens instead of literal values, so
//! the look of the whole application changes here and nowhere else.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, Shadow, Stroke, TextStyle,
};

/// Window and content background.
pub const BACKGROUND: Color32 = Color32::from_rgb(0x0E, 0x11, 0x16);
/// Sidebar and status bar background, slightly darker than the content.
pub const CHROME: Color32 = Color32::from_rgb(0x0A, 0x0C, 0x10);
/// Card background.
pub const SURFACE: Color32 = Color32::from_rgb(0x16, 0x1B, 0x22);
/// Text input and hovered-row background.
pub const SURFACE_RAISED: Color32 = Color32::from_rgb(0x1C, 0x22, 0x2B);
/// Card borders and separators.
pub const BORDER: Color32 = Color32::from_rgb(0x26, 0x2D, 0x38);
/// Primary text.
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xEA, 0xF0);
/// Secondary text: labels, hints, and captions.
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x9A, 0xA4, 0xB2);
/// Primary button fill; white text on it meets WCAG AA.
pub const ACCENT: Color32 = Color32::from_rgb(0x5B, 0x4B, 0xD6);
/// Primary button fill while hovered.
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x6A, 0x5A, 0xE0);
/// Accent used as text or an outline on dark surfaces.
pub const ACCENT_TEXT: Color32 = Color32::from_rgb(0xA9, 0x9C, 0xFF);
/// Text drawn on an [`ACCENT`] fill.
pub const ON_ACCENT: Color32 = Color32::WHITE;
/// Positive state: confirmed, synced, connected.
pub const SUCCESS: Color32 = Color32::from_rgb(0x56, 0xD3, 0x64);
/// Attention state: waiting, syncing, in progress.
pub const WARNING: Color32 = Color32::from_rgb(0xE3, 0xB3, 0x41);
/// Error state.
pub const DANGER: Color32 = Color32::from_rgb(0xFF, 0x7B, 0x72);

/// Dark modules of a QR code; scanners expect dark on light.
pub const QR_DARK: Color32 = Color32::BLACK;
/// Background and quiet zone of a QR code.
pub const QR_LIGHT: Color32 = Color32::WHITE;

/// Share of a tone's color mixed into [`SURFACE`] for badge and notice fills.
const TINT: f32 = 0.16;

/// Extra-small gap, between a label and its value.
pub const SPACE_XS: f32 = 4.0;
/// Small gap, between related controls.
pub const SPACE_SM: f32 = 8.0;
/// Medium gap, between fields in a form.
pub const SPACE_MD: f32 = 12.0;
/// Large gap, between cards.
pub const SPACE_LG: f32 = 20.0;
/// Extra-large gap, between a page header and its content.
pub const SPACE_XL: f32 = 32.0;

/// Width of borders, separators, and focus outlines.
pub const LINE_WIDTH: f32 = 1.0;
/// Corner radius of buttons, inputs, and badges.
pub const RADIUS_SM: u8 = 6;
/// Corner radius of cards and notices.
pub const RADIUS_LG: u8 = 10;
/// Inner padding of cards.
pub const CARD_PADDING: i8 = 18;
/// Page padding inside the central panel.
pub const PAGE_PADDING: i8 = 28;
/// Maximum width of page content, so lines stay readable on wide windows.
pub const CONTENT_WIDTH: f32 = 760.0;
/// Side of a QR code as drawn, including its quiet zone.
pub const QR_SIZE: f32 = 200.0;
/// Width of forms that ask for one thing, such as unlocking.
pub const NARROW_WIDTH: f32 = 460.0;
/// Width of the navigation sidebar.
pub const SIDEBAR_WIDTH: f32 = 200.0;
/// Minimum height of buttons and inputs, a comfortable click target.
pub const CONTROL_HEIGHT: f32 = 34.0;

/// Size of large figures, such as the balance.
pub const DISPLAY_SIZE: f32 = 38.0;
/// Size of page titles.
pub const HEADING_SIZE: f32 = 24.0;
/// Size of card titles.
pub const TITLE_SIZE: f32 = 16.0;
/// Size of body and button text.
pub const BODY_SIZE: f32 = 14.0;
/// Size of monospace text: addresses, hashes, amounts in lists.
pub const MONO_SIZE: f32 = 13.0;
/// Size of captions and badges.
pub const SMALL_SIZE: f32 = 12.0;

/// Meaning of a colored element; widgets pick colors from this, not screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// No particular state.
    Neutral,
    /// Informational, drawn with the accent.
    Info,
    /// Done or healthy.
    Success,
    /// In progress or needs attention.
    Warning,
    /// Failed or broken.
    Danger,
}

impl Tone {
    /// Foreground color for text and icons of this tone.
    pub const fn color(self) -> Color32 {
        match self {
            Self::Neutral => TEXT_MUTED,
            Self::Info => ACCENT_TEXT,
            Self::Success => SUCCESS,
            Self::Warning => WARNING,
            Self::Danger => DANGER,
        }
    }

    /// Subtle background fill for badges and notices of this tone.
    pub fn fill(self) -> Color32 {
        SURFACE.lerp_to_gamma(self.color(), TINT)
    }
}

/// Font for large figures such as the balance.
pub fn display_font() -> FontId {
    FontId::proportional(DISPLAY_SIZE)
}

/// Installs the theme on a context. Call once at startup.
pub fn apply(ctx: &egui::Context) {
    ctx.set_visuals(visuals());
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(HEADING_SIZE)),
            (TextStyle::Body, FontId::proportional(BODY_SIZE)),
            (TextStyle::Button, FontId::proportional(BODY_SIZE)),
            (
                TextStyle::Monospace,
                FontId::new(MONO_SIZE, FontFamily::Monospace),
            ),
            (TextStyle::Small, FontId::proportional(SMALL_SIZE)),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(SPACE_SM, SPACE_SM);
        style.spacing.button_padding = egui::vec2(SPACE_MD + SPACE_XS, SPACE_SM);
        style.spacing.interact_size.y = CONTROL_HEIGHT;
        style.spacing.text_edit_width = NARROW_WIDTH;
    });
}

fn visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = BACKGROUND;
    visuals.window_fill = SURFACE;
    visuals.window_stroke = Stroke::new(LINE_WIDTH, BORDER);
    visuals.window_corner_radius = CornerRadius::same(RADIUS_LG);
    visuals.window_shadow = Shadow::NONE;
    visuals.popup_shadow = Shadow::NONE;
    visuals.extreme_bg_color = SURFACE_RAISED;
    visuals.faint_bg_color = SURFACE;
    visuals.code_bg_color = SURFACE_RAISED;
    visuals.hyperlink_color = ACCENT_TEXT;
    visuals.warn_fg_color = WARNING;
    visuals.error_fg_color = DANGER;
    visuals.selection.bg_fill = ACCENT;
    visuals.selection.stroke = Stroke::new(LINE_WIDTH, ACCENT_TEXT);
    let radius = CornerRadius::same(RADIUS_SM);
    let widgets = &mut visuals.widgets;
    for (state, fill, stroke) in [
        (&mut widgets.noninteractive, SURFACE, BORDER),
        (&mut widgets.inactive, SURFACE_RAISED, BORDER),
        (&mut widgets.hovered, BORDER, TEXT_MUTED),
        (&mut widgets.active, BORDER, ACCENT_TEXT),
        (&mut widgets.open, SURFACE_RAISED, BORDER),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = Stroke::new(LINE_WIDTH, stroke);
        state.corner_radius = radius;
        state.expansion = 0.0;
    }
    widgets.noninteractive.fg_stroke = Stroke::new(LINE_WIDTH, TEXT_MUTED);
    visuals
}

/// Outer padding of page content.
pub const fn page_margin() -> Margin {
    Margin::same(PAGE_PADDING)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG 2 relative luminance of an sRGB color.
    fn luminance(color: Color32) -> f32 {
        let linear = |c: u8| {
            let c = f32::from(c) / 255.0;
            if c <= 0.040_45 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
    }

    fn contrast(a: Color32, b: Color32) -> f32 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// WCAG AA minimum for body text.
    const AA: f32 = 4.5;

    #[test]
    fn text_colors_meet_wcag_aa_on_every_background() {
        for background in [BACKGROUND, CHROME, SURFACE, SURFACE_RAISED] {
            for text in [TEXT, TEXT_MUTED, ACCENT_TEXT, SUCCESS, WARNING, DANGER] {
                let ratio = contrast(text, background);
                assert!(ratio >= AA, "{text:?} on {background:?}: {ratio}");
            }
        }
    }

    #[test]
    fn button_labels_meet_wcag_aa_on_accent_fills() {
        for fill in [ACCENT, ACCENT_HOVER] {
            assert!(contrast(ON_ACCENT, fill) >= AA, "{fill:?}");
        }
    }

    #[test]
    fn every_tone_stays_readable_on_its_own_tint() {
        for tone in [
            Tone::Neutral,
            Tone::Info,
            Tone::Success,
            Tone::Warning,
            Tone::Danger,
        ] {
            let ratio = contrast(tone.color(), tone.fill());
            assert!(ratio >= AA, "{tone:?}: {ratio}");
        }
    }

    #[test]
    fn tones_are_visually_distinct() {
        let colors = [
            Tone::Neutral,
            Tone::Info,
            Tone::Success,
            Tone::Warning,
            Tone::Danger,
        ]
        .map(Tone::color);
        for (i, a) in colors.iter().enumerate() {
            for b in colors.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
