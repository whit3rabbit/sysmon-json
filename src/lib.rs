// Re-export the primary types and functions
pub mod batch;
pub mod config;
pub mod error;
pub mod converter;
pub mod model;
pub mod merger;
pub mod preprocessor; 

use std::path::Path;
use std::fs;
use error::ConversionError;

pub use batch::BatchProcessor;
pub use config::ProcessingOptions;
pub use config::ProcessingOptionsBuilder;
pub use merger::{merge_configs, merge_configs_with_progress};
pub use model::Value;
pub use preprocessor::preprocess_config; 

/// Converts a Sysmon configuration file between XML and JSON formats.
pub fn convert_file(input: &Path, output: &Path) -> Result<(), ConversionError> {
    // Preprocess the input file
    let preprocessed = preprocess_config(input)
        .map_err(|e| ConversionError::InvalidFile(format!("Preprocessing failed: {:?}", e)))?;
    
    // Write preprocessed content back to a temporary file
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path().join(input.file_name().unwrap());
    std::fs::write(&temp_path, preprocessed)?;
    
    // Get converter and process the preprocessed file
    let converter = converter::get_converter(&temp_path, output)?;
    converter.convert(&temp_path, output)?;
    
    Ok(())
}

/// Converts all Sysmon configuration files in a directory between XML and JSON formats.
pub fn convert_folder(input_dir: &Path, output_dir: &Path) -> Result<(), ConversionError> {
    if !input_dir.is_dir() {
        return Err(ConversionError::InvalidFile(
            format!("Input path is not a directory: {}", input_dir.display())
        ));
    }

    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir)?;

    let entries = fs::read_dir(input_dir)?;
    let mut conversion_errors = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Skip if not a file
        if !path.is_file() {
            continue;
        }

        // Get file extension
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.to_lowercase(),
            None => continue, // Skip files without extension
        };

        // Only process xml or json files
        if ext != "xml" && ext != "json" {
            continue;
        }

        // Create output path with opposite extension
        let new_ext = if ext == "xml" { "json" } else { "xml" };
        let file_name = path.file_name().unwrap();
        let new_name = Path::new(file_name)
            .with_extension(new_ext);
        let output_path = output_dir.join(new_name);

        // Convert the file
        if let Err(e) = convert_file(&path, &output_path) {
            conversion_errors.push((path.clone(), e));
        }
    }

    // If there were any errors, return them as part of the error
    if !conversion_errors.is_empty() {
        let error_msg = conversion_errors
            .into_iter()
            .map(|(path, err)| format!("{}: {}", path.display(), err))
            .collect::<Vec<_>>()
            .join("\n");
        
        return Err(ConversionError::BatchConversionError(error_msg));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_convert_file() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.xml");
        let output_path = temp_dir.path().join("test.json");

        // Create a test XML file
        fs::write(&input_path, "<root><test>value</test></root>").unwrap();

        let result = convert_file(&input_path, &output_path);
        assert!(result.is_ok());
        assert!(output_path.exists());
    }

    #[test]
    fn test_convert_folder() {
        let temp_dir = tempdir().unwrap();
        let input_dir = temp_dir.path().join("input");
        let output_dir = temp_dir.path().join("output");

        fs::create_dir(&input_dir).unwrap();

        // Create test files
        fs::write(
            input_dir.join("test1.xml"),
            "<root><test>value1</test></root>"
        ).unwrap();
        fs::write(
            input_dir.join("test2.xml"),
            "<root><test>value2</test></root>"
        ).unwrap();

        let result = convert_folder(&input_dir, &output_dir);
        assert!(result.is_ok());
        assert!(output_dir.join("test1.json").exists());
        assert!(output_dir.join("test2.json").exists());
    }
}