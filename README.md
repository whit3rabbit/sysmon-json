# Sysmon Config Converter

A Rust library and CLI tool for managing, converting, and merging Sysmon configuration files between XML and JSON formats. This tool provides robust validation, preprocessing, and batch processing capabilities while maintaining configuration integrity.

## Features

- **Format Conversion**
  - Convert between XML and JSON formats while preserving structure
  - Supports both single file and batch directory processing
  - Maintains configuration validation throughout conversion

- **Merging Capabilities**
  - Merge multiple Sysmon configurations into a single unified config
  - Support for combining XML and JSON files in the same merge operation
  - Intelligent rule group handling and deduplication
  - Validates merged configurations against Sysmon schema

- **Path Handling**
  - Normalizes Windows paths across configurations
  - Handles UNC paths correctly
  - Proper drive letter formatting and standardization

- **Validation & Safety**
  - Full schema validation for Sysmon configurations
  - Protection against directory traversal
  - Configurable file size limits
  - Backup creation options
  - Progress tracking for batch operations

- **Performance**
  - Parallel processing for batch operations using rayon
  - Efficient XML and JSON parsing
  - Optimized memory usage for large files

## Installation

### From Source

```bash
cargo install --path .
```

## Usage

### Command Line Interface

```bash
# Convert single file from XML to JSON
sysmon_json -i config.xml -o config.json

# Convert single file from JSON to XML
sysmon_json -i config.json -o config.xml

# Process directory recursively
sysmon_json -r -i input_dir -o output_dir -t xml

# Merge multiple configs
sysmon_json merge -i input_dir -o merged.xml --recursive

# Process with automatic backups
sysmon_json -i config.xml -o config.json --backup
```

### Library Usage

#### Basic Conversion

```rust
use sysmon_json::{convert_file, ProcessingOptions};
use std::path::Path;

// Simple file conversion
convert_file(
    Path::new("input.xml"),
    Path::new("output.json")
)?;

// With custom options
let options = ProcessingOptionsBuilder::new()
    .max_file_size(5 * 1024 * 1024)  // 5MB
    .create_backup(true)
    .verify_output(true)
    .build();

let processor = BatchProcessor::new();
processor.process_directory(
    Path::new("input_dir"),
    Path::new("output_dir"),
    true,  // recursive
    &options
)?;
```

#### Merging Configurations

```rust
use sysmon_json::merge_configs;

// Merge multiple configs into one
merge_configs(
    Path::new("configs_dir"),
    Path::new("merged_config.xml"),
    true  // recursive
)?;

// With progress tracking
let progress = ProgressReporter::new(total_files);
merge_configs_with_progress(
    Path::new("configs_dir"),
    Path::new("merged_config.xml"),
    true,
    &progress
)?;
```

#### Custom Processing

```rust
use sysmon_json::preprocessor::preprocess_config;

// Preprocess a configuration
let processed = preprocess_config(Path::new("config.xml"))?;

// Convert between formats programmatically
let converter = get_converter(&input_path, &output_path)?;
converter.convert(&input_path, &output_path)?;
```

## Configuration Options

The `ProcessingOptions` struct provides fine-grained control over conversion behavior:

```rust
let options = ProcessingOptionsBuilder::new()
    .max_file_size(10 * 1024 * 1024)  // 10MB limit
    .max_depth(10)                     // Max directory depth
    .workers(Some(4))                  // Number of worker threads
    .ignore_patterns(Some(vec![       // Files to ignore
        String::from("temp"),
        String::from("backup")
    ]))
    .create_backup(true)              // Create backups
    .verify_output(true)              // Validate output
    .silent(false)                    // Show progress
    .show_stats(true)                 // Show completion stats
    .build();
```

## Error Handling

The library provides detailed error types for different failure scenarios:

- `ConversionError`: For format conversion issues
- `ValidationError`: For Sysmon schema validation failures
- `PreprocessError`: For preprocessing failures
- `BatchError`: For batch processing issues

## Examples

### Merging Configurations

```rust
use sysmon_json::merger::ConfigMerger;

let mut merger = ConfigMerger::new();
let merged = merger.merge_directory(
    Path::new("configs"),
    true  // recursive
)?;

// Access merge statistics
println!("Processed {} files", merger.processed_files_count());
println!("Combined {} rules", merger.current_rules_count());
```

### Batch Processing with Progress

```rust
use sysmon_json::batch::{BatchProcessor, ProgressReporter};

let processor = BatchProcessor::new();
let progress = ProgressReporter::new(total_files);

let stats = processor.process_directory_with_progress(
    Path::new("input"),
    Path::new("output"),
    true,
    &options,
    &progress
)?;

println!("Processed: {}, Errors: {}", stats.processed, stats.errors);
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see the [LICENSE](LICENSE) file for details