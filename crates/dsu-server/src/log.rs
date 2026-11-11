//! The server's log: one line per refused request (docs/design.md section 1), on stderr in
//! `serve`.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

/// Where log lines go. Cloning shares the sink.
#[derive(Clone)]
pub struct Log {
    sink: Arc<Mutex<dyn Write + Send>>,
}

impl Log {
    /// A log that writes to `sink`; tests keep their own handle on it to read the lines.
    pub fn new(sink: Arc<Mutex<dyn Write + Send>>) -> Log {
        Log { sink }
    }

    /// The process's stderr.
    pub fn stderr() -> Log {
        Log::new(Arc::new(Mutex::new(std::io::stderr())))
    }

    /// Writes `line` and a newline. A write that fails is dropped: logging never fails a
    /// request.
    pub fn line(&self, line: &str) {
        let mut sink = self.sink.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(sink, "{line}").and_then(|()| sink.flush());
    }
}
