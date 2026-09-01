fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "SyncPlus",
        native_options,
        Box::new(|_creation_context| Ok(Box::new(syncplus::SyncPlusApp::new()?))),
    )
}
