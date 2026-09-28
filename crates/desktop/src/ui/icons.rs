//! Line icons drawn with the painter, in the same stroke style as the NULL
//! mark, so they stay sharp at any scale and need no icon font or images.
//!
//! Each icon is a set of polylines on a 16×16 grid, scaled into the target
//! rectangle. Strokes have round caps and joins like the brand artwork.

use std::f32::consts::PI;

use eframe::egui::{Color32, Painter, Pos2, Rect, Stroke};

/// Side of the grid icons are designed on.
const GRID: f32 = 16.0;
/// Stroke width on that grid.
const GRID_STROKE: f32 = 1.5;
/// Points per quarter turn when approximating arcs.
const ARC_SEGMENTS_PER_QUARTER: usize = 6;

/// Icons used in navigation and actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// A 2×2 grid: the overview dashboard.
    Overview,
    /// An arrow into a tray.
    Receive,
    /// An arrow out of a tray.
    Send,
    /// A pulse line: recent activity.
    Activity,
    /// Two stacked servers: the node.
    Node,
}

impl Icon {
    /// The icon's polylines on the 16×16 grid.
    fn paths(self) -> Vec<Vec<Pos2>> {
        let p = |x: f32, y: f32| Pos2::new(x, y);
        match self {
            Self::Overview => [(2.0, 2.0), (9.0, 2.0), (2.0, 9.0), (9.0, 9.0)]
                .into_iter()
                .map(|(x, y)| rectangle(p(x, y), p(x + 5.0, y + 5.0)))
                .collect(),
            Self::Receive => vec![
                vec![p(8.0, 2.0), p(8.0, 10.0)],
                vec![p(4.5, 6.5), p(8.0, 10.0), p(11.5, 6.5)],
                tray(),
            ],
            Self::Send => vec![
                vec![p(8.0, 10.0), p(8.0, 2.0)],
                vec![p(4.5, 5.5), p(8.0, 2.0), p(11.5, 5.5)],
                tray(),
            ],
            Self::Activity => vec![vec![
                p(1.5, 8.0),
                p(4.5, 8.0),
                p(6.5, 3.0),
                p(9.5, 13.0),
                p(11.5, 8.0),
                p(14.5, 8.0),
            ]],
            Self::Node => vec![
                rectangle(p(2.0, 2.5), p(14.0, 7.0)),
                rectangle(p(2.0, 9.0), p(14.0, 13.5)),
                vec![p(4.5, 4.75), p(4.6, 4.75)],
                vec![p(4.5, 11.25), p(4.6, 11.25)],
            ],
        }
    }

    /// Draws the icon to fill `rect`, keeping its square proportions.
    pub fn paint(self, painter: &Painter, rect: Rect, color: Color32) {
        let side = rect.width().min(rect.height());
        let scale = side / GRID;
        let (left, top) = (rect.center().x - side / 2.0, rect.center().y - side / 2.0);
        let stroke = Stroke::new(GRID_STROKE * scale, color);
        for path in self.paths() {
            let points: Vec<Pos2> = path
                .iter()
                .map(|q| Pos2::new(left + q.x * scale, top + q.y * scale))
                .collect();
            stroke_path(painter, &points, stroke);
        }
    }
}

/// The open tray under the receive and send arrows.
fn tray() -> Vec<Pos2> {
    vec![
        Pos2::new(2.0, 10.5),
        Pos2::new(2.0, 14.0),
        Pos2::new(14.0, 14.0),
        Pos2::new(14.0, 10.5),
    ]
}

/// A closed rectangle outline from `min` to `max`.
fn rectangle(min: Pos2, max: Pos2) -> Vec<Pos2> {
    vec![
        min,
        Pos2::new(max.x, min.y),
        max,
        Pos2::new(min.x, max.y),
        min,
    ]
}

/// Points along a circular arc around `center` from angle `from` to `to`,
/// in radians, with screen coordinates (y grows downwards).
pub fn arc(center: Pos2, radius: f32, from: f32, to: f32) -> Vec<Pos2> {
    // Arcs here span at most a full turn: at most 4 quarters.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let quarters = ((to - from).abs() / (PI / 2.0)).ceil().clamp(1.0, 4.0) as usize;
    let steps = quarters.saturating_mul(ARC_SEGMENTS_PER_QUARTER);
    (0..=steps)
        .map(|i| {
            // Step counts are at most 24, exact in f32.
            #[allow(clippy::cast_precision_loss)]
            let t = from + (to - from) * (i as f32 / steps as f32);
            Pos2::new(center.x + radius * t.cos(), center.y + radius * t.sin())
        })
        .collect()
}

/// Strokes a polyline with round caps and joins, as the brand artwork does:
/// egui's own line ends are square.
pub fn stroke_path(painter: &Painter, points: &[Pos2], stroke: Stroke) {
    painter.add(eframe::egui::Shape::line(points.to_vec(), stroke));
    for point in points {
        painter.circle_filled(*point, stroke.width / 2.0, stroke.color);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Icon; 5] = [
        Icon::Overview,
        Icon::Receive,
        Icon::Send,
        Icon::Activity,
        Icon::Node,
    ];

    #[test]
    fn every_icon_stays_inside_its_grid() {
        for icon in ALL {
            let paths = icon.paths();
            assert!(!paths.is_empty(), "{icon:?}");
            for point in paths.iter().flatten() {
                assert!(
                    (0.0..=GRID).contains(&point.x) && (0.0..=GRID).contains(&point.y),
                    "{icon:?} {point:?}"
                );
            }
        }
    }

    #[test]
    fn icons_are_distinct() {
        for (i, a) in ALL.iter().enumerate() {
            for b in ALL.iter().skip(i + 1) {
                assert_ne!(a.paths(), b.paths(), "{a:?} {b:?}");
            }
        }
    }

    #[test]
    fn arcs_start_and_end_on_the_circle_at_the_given_angles() {
        let points = arc(Pos2::new(8.0, 8.0), 2.0, PI, 2.0 * PI);
        let (first, last) = (points[0], points[points.len() - 1]);
        assert!((first - Pos2::new(6.0, 8.0)).length() < 1e-4);
        assert!((last - Pos2::new(10.0, 8.0)).length() < 1e-4);
        // Screen coordinates: the half turn from π to 2π bulges upwards.
        assert!(points.iter().all(|p| p.y <= 8.0 + 1e-4));
        assert!(points
            .iter()
            .all(|p| ((*p - Pos2::new(8.0, 8.0)).length() - 2.0).abs() < 1e-4));
    }
}
