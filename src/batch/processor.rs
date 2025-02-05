use rayon::prelude::*;
use walkdir::WalkDir;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use crate::config::ProcessingOptions;
use crate::error::ConversionError;
use super::progress::ProgressReporter;

/// Handles batch processing of multiple Sysmon configuration files
pub struct BatchProcessor {
    processed_count: Arc<AtomicUsize>,
    error_count: Arc<AtomicUsize>,
}

/// Statistics from batch processing operation
#[derive(Debug)]
pub struct BatchProcessingStats {
    /// Number of files successfully processed
    pub processed: usize,
    /// Number of files that failed to process
    pub errors: usize,
}

impl BatchProcessor {
    /// Creates a new BatchProcessor instance
    pub fn new() -> Self {
        Self {
            processed_count: Arc::new(AtomicUsize::new(0)),
            error_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Process a directory of files with progress tracking
    pub fn process_directory_with_progress(
        &self,
        input_dir: &Path,
        output_dir: &Path,
        recursive: bool,
        options: &ProcessingOptions,
        progress: &ProgressReporter,
    ) -> Result<BatchProcessingStats, ConversionError> {
        // Create output directory if it doesn't exist
        std::fs::create_dir_all(output_dir)?;

        let walker = if recursive {
            WalkDir::new(input_dir)
        } else {
            WalkDir::new(input_dir).max_depth(1)
        };

        // Collect files first to enable parallel processing
        let files: Vec<_> = walker
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .collect();

        // Process files in parallel using rayon
        files.par_iter().for_each(|entry| {
            let result = self.process_single_file(entry.path(), output_dir, options);
            
            match result {
                Ok(_) => {
                    self.processed_count.fetch_add(1, Ordering::SeqCst);
                    progress.increment();
                }
                Err(e) => {
                    eprintln!("Error processing {}: {}", entry.path().display(), e);
                    self.error_count.fetch_add(1, Ordering::SeqCst);
                    progress.increment();
                }
            }
        });

        Ok(BatchProcessingStats {
            processed: self.processed_count.load(Ordering::SeqCst),
            errors: self.error_count.load(Ordering::SeqCst),
        })
    }

    /// Process a directory of files
    pub fn process_directory(
        &self,
        input_dir: &Path,
        output_dir: &Path,
        recursive: bool,
        options: &ProcessingOptions,
    ) -> Result<BatchProcessingStats, ConversionError> {
        // Create output directory if it doesn't exist
        std::fs::create_dir_all(output_dir)?;

        let walker = if recursive {
            WalkDir::new(input_dir)
        } else {
            WalkDir::new(input_dir).max_depth(1)
        };

        // Collect files first to enable parallel processing
        let files: Vec<_> = walker
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .collect();

        // Process files in parallel using rayon
        files.par_iter().for_each(|entry| {
            let result = self.process_single_file(entry.path(), output_dir, options);
            
            match result {
                Ok(_) => {
                    self.processed_count.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    eprintln!("Error processing {}: {}", entry.path().display(), e);
                    self.error_count.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        Ok(BatchProcessingStats {
            processed: self.processed_count.load(Ordering::SeqCst),
            errors: self.error_count.load(Ordering::SeqCst),
        })
    }

    fn process_single_file(
        &self,
        input: &Path,
        output_dir: &Path,
        options: &ProcessingOptions,
    ) -> Result<(), ConversionError> {
        // Skip files larger than max_size
        if let Ok(metadata) = input.metadata() {
            if metadata.len() > options.max_file_size {
                return Err(ConversionError::InvalidFile(
                    format!("File too large: {}", input.display())
                ));
            }
        }

        // Skip files matching ignore patterns
        if let Some(patterns) = &options.ignore_patterns {
            if let Some(file_name) = input.file_name().and_then(|n| n.to_str()) {
                if patterns.iter().any(|p| file_name.contains(p)) {
                    return Ok(());
                }
            }
        }

        // Determine output path
        let file_name = input.file_name().ok_or_else(|| {
            ConversionError::InvalidFile("Invalid input filename".into())
        })?;
        
        let new_extension = if input.extension().and_then(|e| e.to_str()) == Some("xml") {
            "json"
        } else {
            "xml"
        };

        let output_path = output_dir.join(file_name).with_extension(new_extension);

        // Create backup if enabled
        if options.create_backup && output_path.exists() {
            let backup_path = output_path.with_extension("bak");
            std::fs::copy(&output_path, &backup_path)?;
        }

        // Convert the file
        crate::convert_file(input, &output_path)
    }
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new()
    }
}