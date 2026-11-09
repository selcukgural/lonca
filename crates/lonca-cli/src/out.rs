//! Standard output that a closed pipe does not break.
//!
//! `println!` panics when stdout fails, and Rust ignores SIGPIPE, so
//! `lonca status | head` ended in a panic. Output goes through [`out!`] and
//! [`outln!`] instead: once the reader is gone (`BrokenPipe`), the rest is
//! dropped and the command goes on to its end, so a command that writes as
//! it goes (a key rotation over several repositories) is never cut off
//! halfway. `main` then exits as the command did, without a panic. Any other
//! write error (a full disk under a redirect) is kept and reported, because
//! output lost there is not what the reader asked for.

use std::fmt;
use std::io::{self, ErrorKind, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Where stdout stands: closed by its reader, or failed otherwise.
struct Sink {
    /// The reader closed stdout; nothing more is written.
    closed: AtomicBool,
    /// The first write error that was not a closed pipe.
    failed: Mutex<Option<String>>,
}

impl Sink {
    const fn new() -> Self {
        Sink {
            closed: AtomicBool::new(false),
            failed: Mutex::new(None),
        }
    }

    fn write(&self, w: &mut impl Write, args: fmt::Arguments) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let Err(e) = w.write_fmt(args).and_then(|()| w.flush()) else {
            return;
        };
        if e.kind() == ErrorKind::BrokenPipe {
            self.closed.store(true, Ordering::Relaxed);
        } else if let Ok(mut f) = self.failed.lock() {
            f.get_or_insert_with(|| e.to_string());
        }
    }

    fn failed(&self) -> Option<String> {
        self.failed.lock().ok().and_then(|f| f.clone())
    }
}

static STDOUT: Sink = Sink::new();

/// Writes `args` to stdout, unless it is closed. See the module docs.
pub fn write(args: fmt::Arguments) {
    STDOUT.write(&mut io::stdout().lock(), args);
}

/// The first write to stdout that failed for another reason than a closed
/// pipe.
pub fn failed() -> Option<String> {
    STDOUT.failed()
}

/// The reader went away: an error that only says so ends the command
/// quietly, as `git log | head` does.
pub fn is_closed_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == ErrorKind::BrokenPipe)
    })
}

/// `print!` that survives a closed stdout.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::out::write(format_args!($($arg)*))
    };
}

/// `println!` that survives a closed stdout.
macro_rules! outln {
    () => {
        $crate::out::write(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::out::write(format_args!("{}\n", format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_pipe_is_a_closed_pipe_and_other_errors_are_not() {
        let pipe = anyhow::Error::new(io::Error::from(ErrorKind::BrokenPipe)).context("writing");
        assert!(is_closed_pipe(&pipe));
        let full = anyhow::Error::new(io::Error::from(ErrorKind::StorageFull));
        assert!(!is_closed_pipe(&full));
        assert!(!is_closed_pipe(&anyhow::anyhow!("broken pipe")));
    }

    /// Takes writes until `fail` is set, then fails each with it.
    struct Reader {
        got: Vec<u8>,
        writes: usize,
        fail: Option<ErrorKind>,
    }

    impl Write for Reader {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            match self.fail {
                Some(kind) => Err(io::Error::from(kind)),
                None => {
                    self.got.extend_from_slice(buf);
                    Ok(buf.len())
                }
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn reader() -> Reader {
        Reader {
            got: vec![],
            writes: 0,
            fail: None,
        }
    }

    #[test]
    fn once_the_reader_is_gone_nothing_more_is_written_and_nothing_fails() {
        let sink = Sink::new();
        let mut r = reader();
        sink.write(&mut r, format_args!("one\n"));
        assert_eq!(r.got, b"one\n");
        r.fail = Some(ErrorKind::BrokenPipe);
        sink.write(&mut r, format_args!("two\n"));
        let tried = r.writes;
        sink.write(&mut r, format_args!("three\n"));
        assert_eq!(r.writes, tried, "a closed stdout is not written again");
        assert_eq!(sink.failed(), None, "a closed pipe is no failure");
    }

    #[test]
    fn another_write_error_is_kept_and_output_goes_on() {
        let sink = Sink::new();
        let mut r = reader();
        r.fail = Some(ErrorKind::StorageFull);
        sink.write(&mut r, format_args!("one\n"));
        let first = sink.failed().expect("kept");
        r.fail = Some(ErrorKind::PermissionDenied);
        sink.write(&mut r, format_args!("two\n"));
        assert_eq!(sink.failed(), Some(first), "the first error is kept");
        r.fail = None;
        sink.write(&mut r, format_args!("three\n"));
        assert_eq!(r.got, b"three\n", "a failed write does not close stdout");
    }
}
