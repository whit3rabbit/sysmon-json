use serde::{Deserialize, Serialize};

/// Options for controlling Sysmon configuration processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingOptions {
    /// Maximum allowed file size in bytes
    pub max_file_size: u64,
    
    /// Maximum directory recursion depth
    pub max_depth: u32,
    
    /// Optional number of worker threads
    pub workers: Option<usize>,
    
    /// Optional patterns to ignore when processing files
    pub ignore_patterns: Option<Vec<String>>,
    
    /// Whether to create backups of existing files
    pub create_backup: bool,
    
    /// Whether to verify output after conversion
    pub verify_output: bool,
    
    /// Whether to suppress output
    pub silent: bool,
    
    /// Whether to show processing statistics
    pub show_stats: bool,
}

impl Default for ProcessingOptions {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_depth: 10,
            workers: None,
            ignore_patterns: None,
            create_backup: false,
            verify_output: true,
            silent: false,
            show_stats: true,
        }
    }
}

/// Builder pattern for ProcessingOptions
pub struct ProcessingOptionsBuilder {
    options: ProcessingOptions,
}

impl ProcessingOptionsBuilder {
    /// Creates a new ProcessingOptionsBuilder with default values
    pub fn new() -> Self {
        Self {
            options: ProcessingOptions::default(),
        }
    }

    /// Sets the maximum file size in bytes
    pub fn max_file_size(mut self, size: u64) -> Self {
        self.options.max_file_size = size;
        self
    }

    /// Sets the maximum recursion depth
    pub fn max_depth(mut self, depth: u32) -> Self {
        self.options.max_depth = depth;
        self
    }

    /// Sets the number of worker threads
    pub fn workers(mut self, workers: Option<usize>) -> Self {
        self.options.workers = workers;
        self
    }

    /// Sets patterns to ignore
    pub fn ignore_patterns(mut self, patterns: Option<Vec<String>>) -> Self {
        self.options.ignore_patterns = patterns;
        self
    }

    /// Sets whether to create backups
    pub fn create_backup(mut self, create: bool) -> Self {
        self.options.create_backup = create;
        self
    }

    /// Sets whether to verify output
    pub fn verify_output(mut self, verify: bool) -> Self {
        self.options.verify_output = verify;
        self
    }

    /// Sets whether to suppress output
    pub fn silent(mut self, silent: bool) -> Self {
        self.options.silent = silent;
        self
    }

    /// Sets whether to show statistics
    pub fn show_stats(mut self, show: bool) -> Self {
        self.options.show_stats = show;
        self
    }

    /// Builds the ProcessingOptions
    pub fn build(self) -> ProcessingOptions {
        self.options
    }
}

impl Default for ProcessingOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let options = ProcessingOptions::default();
        assert_eq!(options.max_file_size, 10 * 1024 * 1024);
        assert_eq!(options.max_depth, 10);
        assert!(options.workers.is_none());
        assert!(options.ignore_patterns.is_none());
        assert!(!options.create_backup);
        assert!(options.verify_output);
        assert!(!options.silent);
        assert!(options.show_stats);
    }

    #[test]
    fn test_builder_pattern() {
        let test_patterns = vec!["test".to_string(), "temp".to_string()];
        let options = ProcessingOptionsBuilder::new()
            .max_file_size(5 * 1024 * 1024)
            .max_depth(5)
            .workers(Some(4))
            .ignore_patterns(Some(test_patterns.clone()))
            .create_backup(true)
            .silent(true)
            .verify_output(false)
            .show_stats(false)
            .build();

        assert_eq!(options.max_file_size, 5 * 1024 * 1024);
        assert_eq!(options.max_depth, 5);
        assert_eq!(options.workers, Some(4));
        assert_eq!(options.ignore_patterns, Some(test_patterns));
        assert!(options.create_backup);
        assert!(options.silent);
        assert!(!options.verify_output);
        assert!(!options.show_stats);
    }

    #[test]
    fn test_partial_builder_pattern() {
        let options = ProcessingOptionsBuilder::new()
            .max_file_size(20 * 1024 * 1024)
            .create_backup(true)
            .build();

        assert_eq!(options.max_file_size, 20 * 1024 * 1024);
        assert!(options.create_backup);
        // Other fields should have default values
        assert_eq!(options.max_depth, 10);
        assert!(options.workers.is_none());
        assert!(options.ignore_patterns.is_none());
        assert!(options.verify_output);
        assert!(!options.silent);
        assert!(options.show_stats);
    }
}