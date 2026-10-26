//! In-memory log for the "Журнал" tab, plus stderr in debug builds.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, reload};

const MAX_LINES: usize = 1000;

/// Shared ring buffer of formatted log lines.
#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<VecDeque<String>>>);

impl LogBuffer {
    /// All lines, oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().iter().cloned().collect()
    }

    /// Removes everything.
    pub fn clear(&self) {
        self.0.lock().clear();
    }

    fn push(&self, line: String) {
        let mut q = self.0.lock();
        if q.len() >= MAX_LINES {
            q.pop_front();
        }
        q.push_back(line);
    }
}

/// Collects one event and stores it on drop.
pub struct LineWriter {
    buf: Vec<u8>,
    target: LogBuffer,
}

impl Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.buf);
        let line = text.trim_end();
        if !line.is_empty() {
            #[cfg(debug_assertions)]
            eprintln!("{line}");
            self.target.push(line.to_string());
        }
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LineWriter;
    fn make_writer(&'a self) -> LineWriter {
        LineWriter {
            buf: Vec::new(),
            target: self.clone(),
        }
    }
}

/// Changes the log level at run time.
pub type LevelHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

fn filter(level: &str) -> EnvFilter {
    let level = match level {
        "error" | "warn" | "info" | "debug" | "trace" => level,
        _ => "info",
    };
    // Third-party crates stay quiet unless something is wrong.
    EnvFilter::new(format!(
        "warn,unbihex_engine={level},unbihex_client_core={level},unbihex_client_lib={level}"
    ))
}

/// Installs the global subscriber.
pub fn init(level: &str) -> (LogBuffer, Option<LevelHandle>) {
    let buffer = LogBuffer::default();
    let (layer, handle) = reload::Layer::new(filter(level));
    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_writer(buffer.clone());
    let ok = tracing_subscriber::registry().with(layer).with(fmt).try_init().is_ok();
    (buffer, ok.then_some(handle))
}

/// Applies a new level.
pub fn set_level(handle: &Option<LevelHandle>, level: &str) {
    if let Some(h) = handle {
        let _ = h.reload(filter(level));
    }
}
