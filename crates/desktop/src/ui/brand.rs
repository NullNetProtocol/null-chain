//! The NULL logo and app icon from `NullNetProtocol/brand-assets`.
//!
//! The mark (∅) and the NULL wordmark are stroke drawings, so they are
//! drawn here from the exact geometry of `banner-white.svg` and
//! `icon-white.svg` instead of shipping images. The brand rules apply:
//! white on dark, never stretched or recolored. The window icon is the
//! official `icon.png`, embedded unchanged.

use std::f32::consts::PI;

use eframe::egui::{IconData, Pos2, Rect, Response, Sense, Stroke, Ui, Vec2};

use super::icons::{arc, stroke_path};
use super::theme;

/// The official app icon, 1024×1024, dark background.
pub const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");

/// Stroke width of the banner's mark and letters, in banner units.
const BANNER_STROKE: f32 = 30.0;
/// The part of the 1360×480 banner holding the mark and wordmark,
/// including half a stroke of margin; the tagline is set as text instead.
const BANNER_CROP: Rect = Rect {
    min: Pos2::new(87.0, 117.0),
    max: Pos2::new(1165.0, 363.0),
};

/// Ring and slash of the mark in the banner: center, radius, and the
/// slash's end points.
const BANNER_RING: (Pos2, f32) = (Pos2::new(210.0, 240.0), 108.0);
const BANNER_SLASH: [Pos2; 2] = [Pos2::new(110.0, 340.0), Pos2::new(310.0, 140.0)];

/// The mark alone, from the 1024×1024 icon.
const ICON_VIEW: f32 = 1024.0;
const ICON_STROKE: f32 = 80.0;
const ICON_RING: (Pos2, f32) = (Pos2::new(512.0, 512.0), 290.0);
const ICON_SLASH: [Pos2; 2] = [Pos2::new(240.0, 784.0), Pos2::new(784.0, 240.0)];

/// The wordmark's letters as polylines in banner units: N, U, L, L.
fn wordmark() -> Vec<Vec<Pos2>> {
    let p = Pos2::new;
    let mut u = vec![p(630.0, 150.0), p(630.0, 260.0)];
    // "A70 70 0 0 0 770 260": the lower half circle between the U's stems.
    u.extend(arc(p(700.0, 260.0), 70.0, PI, 0.0));
    u.push(p(770.0, 150.0));
    vec![
        vec![
            p(420.0, 330.0),
            p(420.0, 150.0),
            p(560.0, 330.0),
            p(560.0, 150.0),
        ],
        u,
        vec![p(840.0, 150.0), p(840.0, 330.0), p(960.0, 330.0)],
        vec![p(1030.0, 150.0), p(1030.0, 330.0), p(1150.0, 330.0)],
    ]
}

/// Maps artwork coordinates in `view` into `rect`, scaled uniformly.
fn transform(view: Rect, rect: Rect) -> impl Fn(Pos2) -> Pos2 {
    let scale = rect.width() / view.width();
    move |point| {
        Pos2::new(
            rect.min.x + (point.x - view.min.x) * scale,
            rect.min.y + (point.y - view.min.y) * scale,
        )
    }
}

/// Draws a ring, slash, and optional letters under `to`, in white.
fn draw(
    ui: &Ui,
    to: &dyn Fn(Pos2) -> Pos2,
    scale: f32,
    stroke: f32,
    ring: (Pos2, f32),
    slash: [Pos2; 2],
    letters: &[Vec<Pos2>],
) {
    let painter = ui.painter();
    let stroke = Stroke::new(stroke * scale, theme::BRAND_MARK);
    painter.circle_stroke(to(ring.0), ring.1 * scale, stroke);
    stroke_path(painter, &slash.map(to), stroke);
    for letter in letters {
        let points: Vec<Pos2> = letter.iter().copied().map(to).collect();
        stroke_path(painter, &points, stroke);
    }
}

/// The ∅ mark and NULL wordmark, `width` points wide.
pub fn logo(ui: &mut Ui, width: f32) -> Response {
    let size = Vec2::new(width, width * BANNER_CROP.height() / BANNER_CROP.width());
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    let scale = rect.width() / BANNER_CROP.width();
    let to = transform(BANNER_CROP, rect);
    draw(
        ui,
        &to,
        scale,
        BANNER_STROKE,
        BANNER_RING,
        BANNER_SLASH,
        &wordmark(),
    );
    response
}

/// The ∅ mark alone in a square of side `size`.
pub fn mark(ui: &mut Ui, size: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let view = Rect::from_min_size(Pos2::ZERO, Vec2::splat(ICON_VIEW));
    let scale = rect.width() / ICON_VIEW;
    let to = transform(view, rect);
    draw(ui, &to, scale, ICON_STROKE, ICON_RING, ICON_SLASH, &[]);
    response
}

/// The window and taskbar icon, or `None` if the embedded PNG is unreadable.
pub fn window_icon() -> Option<IconData> {
    eframe::icon_data::from_png_bytes(ICON_PNG).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui;

    #[test]
    fn the_embedded_icon_is_the_square_brand_icon() {
        let icon = window_icon().unwrap();
        assert_eq!((icon.width, icon.height), (1024, 1024));
        assert_eq!(icon.rgba.len(), 1024 * 1024 * 4);
    }

    #[test]
    fn the_wordmark_fits_the_crop_with_room_for_round_caps() {
        let inner = BANNER_CROP.shrink(BANNER_STROKE / 2.0 - 1e-3);
        for point in wordmark().iter().flatten().chain(&BANNER_SLASH) {
            assert!(inner.contains(*point), "{point:?}");
        }
        let (center, radius) = BANNER_RING;
        let ring = Rect::from_center_size(center, Vec2::splat(2.0 * radius + BANNER_STROKE));
        assert!(BANNER_CROP.contains_rect(ring));
    }

    #[test]
    fn the_u_is_a_lower_half_circle_between_its_stems() {
        let u = &wordmark()[1];
        let bottom = u.iter().map(|p| p.y).fold(f32::MIN, f32::max);
        assert!(
            (bottom - 330.0).abs() < 1e-3,
            "70 below the arc's centre at 260"
        );
        assert_eq!(u.first(), Some(&Pos2::new(630.0, 150.0)));
        assert_eq!(u.last(), Some(&Pos2::new(770.0, 150.0)));
    }

    #[test]
    fn transforms_scale_uniformly_into_the_target() {
        let to = transform(
            Rect::from_min_size(Pos2::ZERO, Vec2::splat(ICON_VIEW)),
            Rect::from_min_size(Pos2::new(10.0, 20.0), Vec2::splat(64.0)),
        );
        assert_eq!(to(Pos2::ZERO), Pos2::new(10.0, 20.0));
        assert_eq!(to(Pos2::new(1024.0, 1024.0)), Pos2::new(74.0, 84.0));
    }

    #[test]
    fn logo_and_mark_render_at_their_requested_size() {
        let ctx = egui::Context::default();
        let mut sizes = Vec::new();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                sizes.push(logo(ui, 140.0).rect.size());
                sizes.push(mark(ui, 48.0).rect.size());
            });
        });
        assert!((sizes[0].x - 140.0).abs() < 1e-3);
        // egui rounds allocations to whole pixels; the aspect is kept to within one.
        assert!(
            (sizes[0].y - 140.0 * 246.0 / 1078.0).abs() <= 1.0,
            "{:?}",
            sizes[0]
        );
        assert_eq!(sizes[1], Vec2::splat(48.0));
    }
}
