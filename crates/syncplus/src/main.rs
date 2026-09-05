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
            viewport: eframe::egui::ViewportBuilder::default()
                .with_title("SyncPlus")
                .with_app_id("syncplus")
                .with_inner_size([1280.0, 760.0])
                .with_min_inner_size([960.0, 600.0])
                .with_icon(syncplus::window_icon()),
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
