use std::{
    sync::{
        Arc, Mutex, OnceLock,
        mpsc::{self, Receiver, Sender},
    },
    time::{Duration, Instant},
};

use eframe::egui;

pub const TRAY_UNAVAILABLE_COPY: &str =
    "The system tray is not available, so the window stays open. Use Exit when you want to quit.";

const TRAY_RETRY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    ShowWindow,
    Quit,
}

struct SyncPlusTray {
    commands: Sender<TrayCommand>,
    repaint_context: Arc<Mutex<Option<egui::Context>>>,
}

impl SyncPlusTray {
    fn dispatch(&self, command: TrayCommand) {
        let _ = self.commands.send(command);
        if let Ok(context) = self.repaint_context.lock()
            && let Some(context) = context.as_ref()
        {
            context.request_repaint();
        }
    }
}

impl ksni::Tray for SyncPlusTray {
    const MENU_ON_ACTIVATE: bool = false;

    fn id(&self) -> String {
        "syncplus".to_owned()
    }

    fn title(&self) -> String {
        "SyncPlus".to_owned()
    }

    fn icon_name(&self) -> String {
        String::new()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![tray_brand_icon()]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: vec![tray_brand_icon()],
            title: "SyncPlus".to_owned(),
            description: "Left-click shows the window. Right-click opens Show or Quit.".to_owned(),
        }
    }

    fn status(&self) -> ksni::Status {
        ksni::Status::Active
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.dispatch(TrayCommand::ShowWindow);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::{MenuItem, StandardItem};

        vec![
            StandardItem {
                label: "_Show SyncPlus".to_owned(),
                activate: Box::new(|tray: &mut SyncPlusTray| {
                    tray.dispatch(TrayCommand::ShowWindow)
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "_Quit SyncPlus".to_owned(),
                activate: Box::new(|tray: &mut SyncPlusTray| tray.dispatch(TrayCommand::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub struct TrayRuntime {
    _handle: ksni::blocking::Handle<SyncPlusTray>,
    receiver: Receiver<TrayCommand>,
    repaint_context: Arc<Mutex<Option<egui::Context>>>,
}

impl TrayRuntime {
    pub fn start() -> Result<Self, String> {
        use ksni::blocking::TrayMethods;

        let (commands, receiver) = mpsc::channel();
        let repaint_context = Arc::new(Mutex::new(None));
        let tray = SyncPlusTray {
            commands,
            repaint_context: repaint_context.clone(),
        };
        let handle = tray.spawn().map_err(|_| TRAY_UNAVAILABLE_COPY.to_owned())?;
        Ok(Self {
            _handle: handle,
            receiver,
            repaint_context,
        })
    }

    pub fn bind_repaint_context(&self, context: &egui::Context) {
        if let Ok(mut repaint_context) = self.repaint_context.lock() {
            *repaint_context = Some(context.clone());
        }
    }

    pub fn take_commands(&self) -> Vec<TrayCommand> {
        self.receiver.try_iter().collect()
    }
}

pub fn should_retry_tray(retry_at: Option<Instant>, now: Instant) -> bool {
    retry_at.is_none_or(|at| now >= at)
}

pub fn next_tray_retry(now: Instant) -> Instant {
    now + TRAY_RETRY
}

pub fn viewport_close_requested(context: &egui::Context) -> bool {
    context.input(|input| {
        if input.viewport().close_requested() {
            return true;
        }
        input
            .raw
            .viewports
            .get(&input.raw.viewport_id)
            .is_some_and(egui::ViewportInfo::close_requested)
    })
}

fn tray_brand_icon() -> ksni::Icon {
    static ICON: OnceLock<ksni::Icon> = OnceLock::new();
    ICON.get_or_init(|| {
        const PNG: &[u8] =
            include_bytes!("../../../packaging/icons/hicolor/48x48/apps/syncplus.png");
        let decoded = eframe::icon_data::from_png_bytes(PNG)
            .expect("packaged 48px Brand Mark must decode for the tray");
        rgba_to_argb_icon(&decoded)
    })
    .clone()
}

fn rgba_to_argb_icon(icon: &egui::IconData) -> ksni::Icon {
    let mut data = icon.rgba.clone();
    for pixel in data.chunks_exact_mut(4) {
        pixel.rotate_right(1);
    }
    ksni::Icon {
        width: i32::try_from(icon.width).expect("tray icon width fits"),
        height: i32::try_from(icon.height).expect("tray icon height fits"),
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        TRAY_UNAVAILABLE_COPY, next_tray_retry, rgba_to_argb_icon, should_retry_tray,
        viewport_close_requested,
    };
    use eframe::egui;
    use std::time::{Duration, Instant};

    #[test]
    fn tray_unavailable_copy_is_plain_language() {
        let lowered = TRAY_UNAVAILABLE_COPY.to_ascii_lowercase();
        assert!(lowered.contains("system tray is not available"));
        assert!(lowered.contains("window stays open"));
        assert!(!lowered.contains("dbus"));
        assert!(!lowered.contains("statusnotifier"));
        assert!(!lowered.contains("os error"));
        assert!(!lowered.contains("wgpu"));
        assert!(!lowered.contains("sync error"));
    }

    #[test]
    fn brand_mark_pixels_are_converted_to_argb_for_the_tray() {
        let icon = rgba_to_argb_icon(&egui::IconData {
            rgba: vec![0xE0, 0x8A, 0x3C, 0xFF],
            width: 1,
            height: 1,
        });
        assert_eq!(icon.width, 1);
        assert_eq!(icon.height, 1);
        assert_eq!(icon.data, vec![0xFF, 0xE0, 0x8A, 0x3C]);
    }

    #[test]
    fn tray_retry_waits_until_the_backoff_elapses() {
        let now = Instant::now();
        assert!(should_retry_tray(None, now));
        assert!(!should_retry_tray(Some(now + Duration::from_secs(5)), now));
        assert!(should_retry_tray(Some(now), now + Duration::from_millis(1)));
        assert_eq!(next_tray_retry(now) - now, Duration::from_secs(5));
    }

    #[test]
    fn a_hidden_window_close_event_is_visible_to_the_logic_tick() {
        let context = egui::Context::default();
        let mut raw = egui::RawInput::default();
        raw.viewports
            .entry(egui::ViewportId::ROOT)
            .or_default()
            .events
            .push(egui::ViewportEvent::Close);
        let output = context.run_logic(&raw, |context| {
            assert!(
                viewport_close_requested(context),
                "the logic tick must see Close while the window is hidden"
            );
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        });
        let commands = output
            .viewport_commands
            .get(&egui::ViewportId::ROOT)
            .cloned()
            .unwrap_or_default();
        assert!(
            commands.contains(&egui::ViewportCommand::CancelClose),
            "hiding to tray must cancel close so eframe does not quit, got {commands:?}"
        );
    }
}
