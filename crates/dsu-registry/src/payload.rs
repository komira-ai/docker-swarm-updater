//! The request body: nothing, a few bytes, or a byte range of a file streamed in chunks.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf, Take};

/// Most bytes read from the file per body frame.
const CHUNK: usize = 64 * 1024;

enum Data {
    Bytes(Option<Bytes>),
    /// A file positioned at the first byte of the range, limited to the range's length.
    Range(Take<File>),
}

/// A request body of known size.
pub(crate) struct Payload {
    data: Data,
    size: u64,
}

impl Payload {
    /// No body.
    pub(crate) fn empty() -> Self {
        Self::bytes(Bytes::new())
    }

    /// The given bytes, sent as one frame.
    pub(crate) fn bytes(bytes: Bytes) -> Self {
        Self {
            size: bytes.len() as u64,
            data: Data::Bytes(Some(bytes)),
        }
    }

    /// The next `size` bytes of `file`, sent in chunks. A file that ends sooner ends the
    /// body early, which the HTTP layer reports as an error because the length is declared.
    pub(crate) fn range(file: File, size: u64) -> Self {
        Self {
            data: Data::Range(file.take(size)),
            size,
        }
    }
}

impl Body for Payload {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match &mut self.get_mut().data {
            Data::Bytes(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Data::Range(reader) => {
                let mut chunk = vec![0u8; CHUNK];
                let mut buf = ReadBuf::new(&mut chunk);
                match Pin::new(reader).poll_read(cx, &mut buf) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(None);
                        }
                        chunk.truncate(n);
                        Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))))
                    }
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.size)
    }
}
