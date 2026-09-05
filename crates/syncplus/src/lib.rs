// The GUI delegates to the core's evidence-rich APIs. These allowances cover
// intentional constructor/layout trade-offs at that boundary; safety checks
// remain enforced by the core and are covered by its contract tests.
#![allow(
    clippy::field_reassign_with_default,
    clippy::if_same_then_else,
    clippy::too_many_arguments,
    clippy::type_complexity
)]

mod app;
#[cfg(test)]
mod brand_kit;
mod brand_mark;
mod chrome;
mod theme;

pub use app::{EndpointKind, SyncPlusApp, UiValidationError, run_background_scheduler_once};
pub use brand_mark::window_icon;
pub use theme::BrandTheme;
