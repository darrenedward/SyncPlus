use eframe::egui;

fn set_icon_pixel(rgba: &mut [u8], size: usize, x: usize, y: usize, color: [u8; 4]) {
    if x >= size || y >= size {
        return;
    }
    let index = (y * size + x) * 4;
    rgba[index..index + 4].copy_from_slice(&color);
}

fn draw_icon_segment(
    rgba: &mut [u8],
    size: usize,
    start: (f32, f32),
    end: (f32, f32),
    width: f32,
    color: [u8; 4],
) {
    let (x1, y1) = start;
    let (x2, y2) = end;
    let dx = x2 - x1;
    let dy = y2 - y1;
    let length_squared = dx * dx + dy * dy;
    let radius = width / 2.0;
    for y in 0..size {
        for x in 0..size {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            let projection = if length_squared == 0.0 {
                0.0
            } else {
                ((px - x1) * dx + (py - y1) * dy) / length_squared
            }
            .clamp(0.0, 1.0);
            let nearest_x = x1 + projection * dx;
            let nearest_y = y1 + projection * dy;
            let distance_squared = (px - nearest_x).powi(2) + (py - nearest_y).powi(2);
            if distance_squared <= radius * radius {
                set_icon_pixel(rgba, size, x, y, color);
            }
        }
    }
}

fn syncplus_icon() -> egui::IconData {
    let size = 64;
    let mut rgba = vec![0; size * size * 4];
    let dark = syncplus::BrandTheme::dark();
    let background = [dark.canvas.r(), dark.canvas.g(), dark.canvas.b(), 255];
    let copper = [dark.copper.r(), dark.copper.g(), dark.copper.b(), 255];
    let steel = [dark.steel.r(), dark.steel.g(), dark.steel.b(), 255];

    for y in 0..size {
        for x in 0..size {
            let edge_x = x.min(size - 1 - x) as f32;
            let edge_y = y.min(size - 1 - y) as f32;
            if edge_x >= 14.0 || edge_y >= 14.0 || {
                let corner_x = 14.0 - edge_x;
                let corner_y = 14.0 - edge_y;
                corner_x * corner_x + corner_y * corner_y <= 14.0 * 14.0
            } {
                set_icon_pixel(&mut rgba, size, x, y, background);
            }
        }
    }

    let mut top_arc = Vec::new();
    for step in 0..=16 {
        let angle = (200.0 + step as f32 * 7.5).to_radians();
        top_arc.push((32.0 + 16.0 * angle.cos(), 32.0 + 16.0 * angle.sin()));
    }
    for points in top_arc.windows(2) {
        draw_icon_segment(&mut rgba, size, points[0], points[1], 6.0, copper);
    }
    draw_icon_segment(&mut rgba, size, (45.0, 13.0), (49.0, 23.0), 6.0, copper);
    draw_icon_segment(&mut rgba, size, (49.0, 23.0), (38.0, 24.0), 6.0, copper);

    let mut bottom_arc = Vec::new();
    for step in 0..=16 {
        let angle = (20.0 + step as f32 * 7.5).to_radians();
        bottom_arc.push((32.0 + 16.0 * angle.cos(), 32.0 + 16.0 * angle.sin()));
    }
    for points in bottom_arc.windows(2) {
        draw_icon_segment(&mut rgba, size, points[0], points[1], 6.0, steel);
    }
    draw_icon_segment(&mut rgba, size, (19.0, 51.0), (15.0, 41.0), 6.0, steel);
    draw_icon_segment(&mut rgba, size, (15.0, 41.0), (26.0, 40.0), 6.0, steel);

    egui::IconData {
        rgba,
        width: size as u32,
        height: size as u32,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--background-scheduler")
    {
        syncplus::run_background_scheduler_once()
            .map(|_| ())
            .map_err(Into::into)
    } else {
        let native_options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("SyncPlus")
                .with_app_id("syncplus")
                .with_inner_size([1280.0, 760.0])
                .with_min_inner_size([960.0, 600.0])
                .with_icon(syncplus_icon()),
            ..Default::default()
        };
        eframe::run_native(
            "SyncPlus",
            native_options,
            Box::new(|_creation_context| Ok(Box::new(syncplus::SyncPlusApp::new()?))),
        )
        .map_err(Into::into)
    }
}
