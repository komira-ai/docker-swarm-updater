//! The program's view of time. Everything the program itself reads the time of day for,
//! pauses on, or limits with a deadline (waits, the request body, fetches, probes) goes
//! through [`Clock`], so tests drive time by hand. The one exception is the server's
//! request-head and idle timeout, which is hyper's own timer on tokio's clock; tests drive
//! it with tokio's paused time.

use std::future::Future;
use std::pin::{Pin, pin};
use std::task::Poll;
use std::time::Duration;

/// A boxed future, the return type of the async methods of the object-safe traits here.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Time of day, pauses and deadlines.
pub trait Clock: Send + Sync {
    /// The current time of day.
    fn now(&self) -> jiff::Timestamp;

    /// A pause the program chooses to take (a poll interval): resolves after `d`.
    fn sleep(&self, d: Duration) -> BoxFuture<'_, ()>;

    /// A limit on how long something may take (a connect, a read, a probe): resolves once `d`
    /// has passed since this call.
    fn deadline(&self, d: Duration) -> BoxFuture<'_, ()>;
}

/// The real clock: the system's time of day and tokio's timers.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "the real clock is the one place the system time is read"
    )]
    fn now(&self) -> jiff::Timestamp {
        jiff::Timestamp::now()
    }

    fn sleep(&self, d: Duration) -> BoxFuture<'_, ()> {
        Box::pin(tokio::time::sleep(d))
    }

    fn deadline(&self, d: Duration) -> BoxFuture<'_, ()> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// The work did not finish before its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("timed out after {limit:?}")]
pub struct TimedOut {
    /// The limit that passed.
    pub limit: Duration,
}

/// Runs `work` until it finishes or `clock.deadline(limit)` resolves, whichever is first. The
/// deadline is created before `work` is first polled, and `work` wins when both are ready.
pub async fn with_deadline<T>(
    clock: &dyn Clock,
    limit: Duration,
    work: impl Future<Output = T>,
) -> Result<T, TimedOut> {
    let mut deadline = clock.deadline(limit);
    let mut work = pin!(work);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(value) = work.as_mut().poll(cx) {
            return Poll::Ready(Ok(value));
        }
        match deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(TimedOut { limit })),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
