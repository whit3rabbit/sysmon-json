use std::path::Path;
use quick_xml::Reader;
use quick_xml::Writer;
use quick_xml::events::{BytesStart, BytesText, Event};
use sysmon_validator::{
    parse_sysmon_config_from_str,
    validate_sysmon_config,
};
use crate::error::PreprocessError;

pub fn preprocess_config(input_path: &Path) -> Result<String, PreprocessError> {
    // Check file extension
    let _ext = input_path.extension()
        .and_then(|e| e.to_str())
        .ok_or_else(|| PreprocessError::PathError("Missing file extension".to_string()))?
        .to_lowercase();

    // Read and validate the input file
    let content = std::fs::read_to_string(input_path)?;
    let config = parse_sysmon_config_from_str(&content)
        .map_err(PreprocessError::ParserError)?;
    validate_sysmon_config(&config)
        .map_err(PreprocessError::ValidationError)?;

    // Process the content with path normalization
    let preprocessed = process_xml_content(&content)?;
    Ok(preprocessed)
}

fn process_xml_content(content: &str) -> Result<String, PreprocessError> {
    let mut reader = Reader::from_str(content);
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    reader.config_mut().trim_text(true);

    while let Ok(event) = reader.read_event_into(&mut buf) {
        match event {
            Event::Start(ref e) => {
                let name_bytes = e.name();
                let name = name_bytes.as_ref();
                let name_str = std::str::from_utf8(name)?;
                let mut elem = BytesStart::new(name_str);
                
                // Process attributes with path normalization if needed
                for attr_result in e.attributes() {
                    let attr = attr_result.map_err(PreprocessError::from)?;
                    if is_path_attribute(attr.key.as_ref()) {
                        let value = attr.unescape_value()?;
                        if let Ok(normalized) = normalize_path(&value) {
                            elem.push_attribute((
                                std::str::from_utf8(attr.key.as_ref())?,
                                normalized.as_str()
                            ));
                        } else {
                            elem.push_attribute(attr);
                        }
                    } else {
                        elem.push_attribute(attr);
                    }
                }
                
                writer.write_event(Event::Start(elem))?;
            }
            Event::Text(e) => {
                let text = e.unescape()?;
                if is_path_element(&text) {
                    if let Ok(normalized) = normalize_path(&text) {
                        writer.write_event(Event::Text(BytesText::new(&normalized)))?;
                    } else {
                        writer.write_event(Event::Text(e))?;
                    }
                } else {
                    writer.write_event(Event::Text(e))?;
                }
            }
            Event::End(e) => writer.write_event(Event::End(e))?,
            Event::Comment(_) => continue,
            Event::Eof => break,
            _ => writer.write_event(event)?,
        }
        buf.clear();
    }

    String::from_utf8(writer.into_inner())
        .map_err(|e| PreprocessError::PathError(e.to_string()))
}

fn is_path_attribute(key: &[u8]) -> bool {
    matches!(key, b"Image" | b"ImageLoaded" | b"TargetFilename")
}

fn is_path_element(text: &str) -> bool {
    text.contains('\\') || text.contains(':')
}

fn normalize_path(path: &str) -> Result<String, PreprocessError> {
    let path = path.trim();
    
    // Handle UNC paths
    if path.starts_with("\\\\") {
        return Ok(path.replace('/', "\\"));
    }
    
    // Handle drive letter paths
    if path.len() >= 2 && path.chars().nth(1) == Some(':') {
        let normalized = path
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_string();
        
        // Ensure proper drive letter format
        let mut chars: Vec<char> = normalized.chars().collect();
        if chars.len() >= 1 {
            chars[0] = chars[0].to_ascii_uppercase();
        }
        return Ok(chars.into_iter().collect());
    }
    
    // Return original path if it doesn't match Windows path formats
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_path_normalization() {
        assert_eq!(
            normalize_path(r"c:\windows\system32").unwrap(),
            r"C:\windows\system32"
        );
        assert_eq!(
            normalize_path(r"\\server\share").unwrap(),
            r"\\server\share"
        );
        assert_eq!(
            normalize_path(r"c:/windows/system32").unwrap(),
            r"C:\windows\system32"
        );
        // Non-Windows paths are returned as-is
        assert_eq!(
            normalize_path("relative/path").unwrap(),
            "relative/path"
        );
    }

    #[test]
    fn test_config_preprocessing() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.xml");

        let test_xml = r#"
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="test">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">c:/windows/system32/cmd.exe</Image>
                            <CommandLine condition="contains">test</CommandLine>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;

        fs::write(&input_path, test_xml).unwrap();
        
        let result = preprocess_config(&input_path);
        assert!(result.is_ok());
        
        let processed = result.unwrap();
        assert!(processed.contains(r"C:\windows\system32\cmd.exe"));
    }
}