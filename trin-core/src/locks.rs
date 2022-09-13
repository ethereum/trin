use futures::future::FutureExt;
use std::{
    future::Future,
    marker::Sync,
    ops::{Deref, DerefMut},
    panic::Location,
    pin::Pin,
    time::{Duration, Instant},
};
use tokio::{
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::JoinHandle,
};
use tracing::warn;

const ACQUIRE_TIMEOUT_MS: u64 = 100;
const HOLD_TIMEOUT_MS: u64 = 100;

/// Tries to look exactly like a T, by implementing Deref and DerefMut, but emits
/// a warning if drop() is not called soon enough.
pub struct TimedGuard<T> {
    inner: T,
    acquisition_line: u32,
    acquisition_file: &'static str,
    acquisition_time: Instant,
    sleep_task: JoinHandle<()>,
}

impl<T> TimedGuard<T> {
    fn new(inner: T, acquisition_line: u32, acquisition_file: &'static str) -> TimedGuard<T> {
        let now = Instant::now();
        let move_line = acquisition_line;
        let move_file = acquisition_file;
        let handle = tokio::spawn(async move {
            sleep_then_log(move_file, move_line).await;
        });

        TimedGuard {
            inner,
            acquisition_line,
            acquisition_file,
            acquisition_time: now,
            sleep_task: handle,
        }
    }
}

impl<T> Deref for TimedGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for TimedGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Drop for TimedGuard<T> {
    fn drop(&mut self) {
        self.sleep_task.abort();
        let held_for = self.acquisition_time.elapsed().as_millis();
        if held_for > HOLD_TIMEOUT_MS.into() {
            warn!(
                "[{}:{}] lock held for too long: {}ms",
                self.acquisition_file, self.acquisition_line, held_for,
            )
        }
    }
}

async fn sleep_then_log(file: &'static str, line: u32) {
    tokio::time::sleep(Duration::from_millis(HOLD_TIMEOUT_MS)).await;
    warn!(
        "[{}:{}] lock held for over {}ms, not yet released",
        file,
        line,
        HOLD_TIMEOUT_MS.to_string()
    );
}

async fn try_lock<T, Fut>(fut: Fut, file: &'static str, line: u32) -> TimedGuard<T>
where
    Fut: Future<Output = T>,
{
    let acquire_timeout = Duration::from_millis(ACQUIRE_TIMEOUT_MS);
    let sleep = tokio::time::sleep(acquire_timeout).fuse();
    let fused = fut.fuse();

    futures::pin_mut!(sleep, fused);

    let now = Instant::now();

    futures::select! {
        _ = sleep => {
            warn!(
                "[{}:{}] waiting more than {}ms to acquire lock, still waiting",
                file, line, ACQUIRE_TIMEOUT_MS,
            );
        },
        guard = fused => {
            return TimedGuard::new(guard, line, file);
        }
    }

    let guard = fused.await;
    let wait_time = now.elapsed().as_millis();
    warn!("[{}:{}] waited {}ms to acquire lock", file, line, wait_time);

    TimedGuard::new(guard, line, file)
}

// this is a workaround:
// - Rust does not support async in traits
//   https://rust-lang.github.io/async-book/07_workarounds/05_async_in_traits.html
// - async_trait does not give us enough flexibility to implement #[track_caller]
//
// So we manually desugar the async functions and have them return futures
type Async<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// These methods should be used in favor of the stock read() and write() methods.
///
/// These methods emit warnings when the lock takes too long to acquire (meaning it's
/// likely some other user is holding onto the lock for too long).
///
/// They also emit warnings when the returned TimedGuard is kept alive for too long.
/// (The lock is held until the returned TimedGuard is dropped, so it should be dropped
/// as soon as possible!)
pub trait RwLoggingExt<T> {
    #[track_caller]
    fn read_with_warn(&self) -> Async<TimedGuard<RwLockReadGuard<T>>>;

    #[track_caller]
    fn write_with_warn(&self) -> Async<TimedGuard<RwLockWriteGuard<T>>>;
}

impl<T: Send + Sync> RwLoggingExt<T> for RwLock<T> {
    #[track_caller]
    fn read_with_warn(&self) -> Async<TimedGuard<RwLockReadGuard<T>>> {
        let loc = Location::caller();
        Box::pin(try_lock(self.read(), loc.file(), loc.line()))
    }

    #[track_caller]
    fn write_with_warn(&self) -> Async<TimedGuard<RwLockWriteGuard<T>>> {
        let loc = Location::caller();
        Box::pin(try_lock(self.write(), loc.file(), loc.line()))
    }
}
