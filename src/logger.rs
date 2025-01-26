use tracing_subscriber::EnvFilter;
use tracing_subscriber::{filter, fmt, prelude::*};

use tracing_subscriber::fmt::time::FormatTime;

use std::time::SystemTime;

// Custom time formatter to display only hour, minute, and second
struct CustomTime;

impl FormatTime for CustomTime {
    fn format_time(&self, w: &mut fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let secs = now.as_secs();
        let hours = (secs / 3600) % 24;
        let minutes = (secs / 60) % 60;
        let seconds = secs % 60;
        write!(w, "{:02}:{:02}:{:02}  ::", hours, minutes, seconds)
    }
}

// This function will define the level that logs will be displayed and also will create a file
// called spy.log in different paths depending on the platform.
pub fn init(enable_debug: bool) {
    if enable_debug {
        let env_filter_std =
            EnvFilter::new("debug").add_directive("kme_dbg=debug".parse().unwrap());
        registry(env_filter_std, enable_debug);
    } else {
        let env_filter_std = EnvFilter::new("info").add_directive("kme_dbg=info".parse().unwrap());
        registry(env_filter_std, enable_debug);
    }
}

fn registry(env_filter_std: EnvFilter, enable_debug: bool) {
    // Configure the stdout log format based on the `enable_debug` flag.
    let stdout_log = fmt::layer().with_target(false).without_time().event_format(
        fmt::format()
            .with_file(enable_debug) // Include file name only if debug is enabled
            .with_line_number(enable_debug) // Include line number only if debug is enabled
            .with_timer(CustomTime)
            .with_target(false),
    );

    // A layer that collects metrics using specific events.
    let metrics_layer = /* ... */ filter::LevelFilter::INFO;
    tracing_subscriber::registry()
        .with(
            stdout_log
                .with_filter(env_filter_std)
                .with_filter(filter::filter_fn(|metadata| {
                    !metadata.target().starts_with("metrics")
                })),
        )
        .with(
            // Add a filter to the metrics label that *only* enables
            // events whose targets start with `metrics`.
            metrics_layer.with_filter(filter::filter_fn(|metadata| {
                metadata.target().starts_with("metrics")
            })),
        )
        .init();
}
