use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Progress reporter for batch operations
#[derive(Debug)]
pub struct ProgressReporter {
    total: u64,
    processed: Arc<AtomicUsize>,
    start_time: Instant,
}

impl ProgressReporter {
    /// Creates a new ProgressReporter
    pub fn new(total_files: usize) -> Self {
        Self {
            total: total_files as u64,
            processed: Arc::new(AtomicUsize::new(0)),
            start_time: Instant::now(),
        }
    }

    /// Increments the progress counter
    pub fn increment(&self) {
        self.processed.fetch_add(1, Ordering::SeqCst);
    }

    /// Gets the total number of files
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Gets the number of processed files
    pub fn processed(&self) -> usize {
        self.processed.load(Ordering::SeqCst)
    }

    /// Gets the elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Gets a cloned counter for parallel processing
    pub fn get_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.processed)
    }
}