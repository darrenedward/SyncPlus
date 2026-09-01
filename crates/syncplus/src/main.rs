fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args()
        .skip(1)
        .any(|argument| argument == "--background-scheduler")
    {
        syncplus::run_background_scheduler_once()
            .map(|_| ())
            .map_err(Into::into)
    } else {
        let native_options = eframe::NativeOptions::default();
        eframe::run_native(
            "SyncPlus",
            native_options,
            Box::new(|_creation_context| Ok(Box::new(syncplus::SyncPlusApp::new()?))),
        )
        .map_err(Into::into)
    }
}
