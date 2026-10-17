use std::io::Read;
use std::io::Result as IoResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A `Reader` that reads exactly the number of bytes from a sub-reader.
///
/// If the limit is reached, it returns EOF. If the limit is not reached
/// when the destructor is called, the remaining bytes will be read and
/// thrown away.
pub struct EqualReader<R>
where
    R: Read,
{
    reader: R,
    size: usize,
    last_read_signal: Sender<IoResult<()>>,
    // codex-switcher patch: set when the body is not fully consumed, so the owning
    // connection stops parsing further requests from a desynchronized stream.
    poison: Arc<AtomicBool>,
}

impl<R> EqualReader<R>
where
    R: Read,
{
    pub fn new(
        reader: R,
        size: usize,
        poison: Arc<AtomicBool>,
    ) -> (EqualReader<R>, Receiver<IoResult<()>>) {
        let (tx, rx) = channel();

        let r = EqualReader {
            reader,
            size,
            last_read_signal: tx,
            poison,
        };

        (r, rx)
    }
}

impl<R> Read for EqualReader<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.size == 0 {
            return Ok(0);
        }

        let buf = if buf.len() < self.size {
            buf
        } else {
            &mut buf[..self.size]
        };

        match self.reader.read(buf) {
            Ok(len) => {
                self.size -= len;
                Ok(len)
            }
            err @ Err(_) => err,
        }
    }
}

impl<R> Drop for EqualReader<R>
where
    R: Read,
{
    fn drop(&mut self) {
        // codex-switcher patch: the original allocated `vec![0; remaining]` where
        // `remaining` is the client-declared Content-Length, so one request with a
        // huge header aborted the process. Drain through a fixed buffer instead, give
        // up after a byte budget or a time budget, and on give-up (or read error/EOF)
        // poison the connection so the leftover bytes are never parsed as a request.
        // Socket read timeouts (lib.rs) bound each individual read.
        const DRAIN_BUF: usize = 8 * 1024;
        const DRAIN_BUDGET: usize = 16 * 1024 * 1024;
        const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

        if self.size == 0 {
            return;
        }
        // A declared body larger than the budget is not drained at all.
        if self.size > DRAIN_BUDGET {
            self.poison.store(true, Ordering::SeqCst);
            return;
        }

        let deadline = Instant::now() + DRAIN_DEADLINE;
        let mut buf = [0u8; DRAIN_BUF];

        while self.size > 0 {
            if Instant::now() >= deadline {
                break;
            }
            let want = self.size.min(DRAIN_BUF);

            match self.reader.read(&mut buf[..want]) {
                Err(e) => {
                    self.last_read_signal.send(Err(e)).ok();
                    break;
                }
                Ok(0) => {
                    self.last_read_signal.send(Ok(())).ok();
                    break;
                }
                Ok(other) => {
                    self.size -= other;
                }
            }
        }

        // Runs before the inner reader is dropped (and handed to the next request
        // reader), so the connection sees the flag before it can read again.
        if self.size > 0 {
            self.poison.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EqualReader;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn poisons_only_when_body_not_fully_consumed() {
        use std::io::Cursor;

        // Fully drained on drop: not poisoned.
        let poison = flag();
        drop(EqualReader::new(Cursor::new(vec![1u8; 4000]), 4000, poison.clone()));
        assert!(!poison.load(Ordering::SeqCst));

        // Stream ends before the declared length: poisoned.
        let poison = flag();
        drop(EqualReader::new(Cursor::new(vec![1u8; 10]), 4000, poison.clone()));
        assert!(poison.load(Ordering::SeqCst));

        // Declared length above the drain budget: poisoned without reading.
        let poison = flag();
        drop(EqualReader::new(Cursor::new(Vec::new()), usize::MAX, poison.clone()));
        assert!(poison.load(Ordering::SeqCst));
    }

    #[test]
    fn test_limit() {
        use std::io::Cursor;

        let mut org_reader = Cursor::new("hello world".to_string().into_bytes());

        {
            let (mut equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5, flag());

            let mut string = String::new();
            equal_reader.read_to_string(&mut string).unwrap();
            assert_eq!(string, "hello");
        }

        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, " world");
    }

    #[test]
    fn test_not_enough() {
        use std::io::Cursor;

        let mut org_reader = Cursor::new("hello world".to_string().into_bytes());

        {
            let (mut equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5, flag());

            let mut vec = [0];
            equal_reader.read_exact(&mut vec).unwrap();
            assert_eq!(vec[0], b'h');
        }

        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, " world");
    }
}
