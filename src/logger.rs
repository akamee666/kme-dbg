use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{fmt, prelude::*};

pub fn init() {
    let filter = EnvFilter::builder()
        // Set default level to OFF to hide events from other crates
        .with_default_directive(LevelFilter::OFF.into())
        .from_env()
        .unwrap()
        // Add directive for your crate with debug level
        .add_directive("kme_dbg=debug".parse().unwrap());

    let stdout_log = fmt::layer().with_target(false).without_time().event_format(
        fmt::format()
            .with_file(true)
            .with_line_number(true)
            .without_time()
            .with_target(false),
    );

    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter))
        .init();

    info!("Logger was initialized!");
}
