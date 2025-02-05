use crate::{batch::ProgressReporter, error::ConversionError};
use crate::model::Value;
use log::{error, info};
use serde_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use sysmon_validator::parse_sysmon_config_from_str;
use quick_xml::{
    Reader,
    Writer,
    events::{Event, BytesStart, BytesText, BytesDecl},
};
use sysmon_validator::validate_sysmon_config;

/// Merges Sysmon configs from multiple XML/JSON files.
pub struct ConfigMerger {
    schema_version: Option<String>,
    current_rules: Vec<Value>,
    last_processed_file: Option<PathBuf>,
    processed_files_count: usize,
}

impl ConfigMerger {
    pub fn new() -> Self {
        Self {
            schema_version: None,
            current_rules: Vec::new(),
            last_processed_file: None,
            processed_files_count: 0,
        }
    }

    pub fn current_rules_count(&self) -> usize {
        self.current_rules.len()
    }

    pub fn last_processed_file(&self) -> Option<&Path> {
        self.last_processed_file.as_ref().map(|p| p.as_path())
    }

    pub fn processed_files_count(&self) -> usize {
        self.processed_files_count
    }

    /// Process a directory of config files, validating each one
    pub fn merge_directory(&mut self, dir: &Path, recursive: bool) -> Result<Value, ConversionError> {
        let walker = if recursive {
            WalkDir::new(dir)
        } else {
            WalkDir::new(dir).max_depth(1)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_lowercase());

            match ext.as_deref() {
                Some("xml") => {
                    println!("Processing XML file: {:?}", path);
                    let content = std::fs::read_to_string(path)?;
                    let _config = parse_sysmon_config_from_str(&content)?;
                    self.process_xml_file(path)?;
                }
                Some("json") => {
                    println!("Processing JSON file: {:?}", path);
                    let content = std::fs::read_to_string(path)?;
                    let json_value: serde_json::Value = serde_json::from_str(&content)?;
                    self.process_json_value(json_value)?;
                }
                _ => continue,
            }
        }

        println!("Number of rules collected: {}", self.current_rules.len());
        self.build_merged_config()
    }

    fn process_xml_file(&mut self, path: &Path) -> Result<(), ConversionError> {
        self.last_processed_file = Some(path.to_path_buf());
        let content = std::fs::read_to_string(path)?;
    
        // Validate the XML content before processing
        let config = parse_sysmon_config_from_str(&content)
            .map_err(|e| ConversionError::ValidationError(format!("Parse error in {}: {}", path.display(), e)))?;
        
        validate_sysmon_config(&config)
            .map_err(|e| ConversionError::ValidationError(format!("Validation error in {}: {}", path.display(), e)))?;
    
        let mut reader = Reader::from_str(&content);
        let mut buf = Vec::new();
        let mut stack = Vec::new();
        let mut in_event_filtering = false;
        
        // Rest of the processing code remains the same...
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    let mut attributes = HashMap::new();
                    
                    // Process attributes
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| ConversionError::XmlParse(e.into()))?;
                        let key = format!("@{}", String::from_utf8_lossy(attr.key.as_ref()));
                        let value = String::from_utf8_lossy(&attr.value).into_owned();
                        attributes.insert(key, Value::String(value.clone()));
                        
                        if name == "Sysmon" && attr.key.as_ref() == b"schemaversion" && self.schema_version.is_none() {
                            self.schema_version = Some(value);
                        }
                    }
                    
                    stack.push((name.clone(), attributes, HashMap::new()));
                    
                    if name == "EventFiltering" {
                        in_event_filtering = true;
                    }
                },
                Ok(Event::Text(e)) => {
                    if let Some((_, _, ref mut content)) = stack.last_mut() {
                        let text = e.unescape().map_err(|e| ConversionError::XmlParse(e.into()))?.into_owned();
                        if !text.trim().is_empty() {
                            content.insert("$text".to_string(), Value::String(text.trim().to_string()));
                        }
                    }
                },
                Ok(Event::End(e)) => {
                    let end_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    
                    if let Some((element_name, attributes, content)) = stack.pop() {
                        let mut obj = attributes;
                        
                        for (k, v) in content {
                            obj.insert(k, v);
                        }
                        
                        let value = Value::Object(obj);
                        
                        if element_name == "RuleGroup" && in_event_filtering {
                            if let Value::Object(ref rule_obj) = value {
                                for (key, val) in rule_obj {
                                    if !key.starts_with('@') && key != "RuleGroup" {
                                        let mut new_rule = HashMap::new();
                                        for (attr_key, attr_val) in rule_obj.iter() {
                                            if attr_key.starts_with('@') {
                                                new_rule.insert(attr_key.clone(), attr_val.clone());
                                            }
                                        }
                                        new_rule.insert(key.clone(), val.clone());
                                        self.current_rules.push(Value::Object(new_rule));
                                    }
                                }
                            }
                        }
                        
                        if let Some((_, _, ref mut parent_content)) = stack.last_mut() {
                            parent_content.insert(element_name, value);
                        }
                    }
                    
                    if end_name == "EventFiltering" {
                        in_event_filtering = false;
                    }
                },
                Ok(Event::Eof) => break,
                Err(e) => return Err(ConversionError::XmlParse(e.into())),
                _ => (),
            }
            buf.clear();
        }
        self.processed_files_count += 1;      
        Ok(())
    }

    fn process_json_value(&mut self, json_value: serde_json::Value) -> Result<(), ConversionError> {
        match json_value {
            serde_json::Value::Object(obj) => {
                // If missing, store the first discovered schema version
                if self.schema_version.is_none() {
                    if let Some(ver) = obj.get("@schemaversion") {
                        if let Some(ver_str) = ver.as_str() {
                            self.schema_version = Some(ver_str.to_string());
                        }
                    }
                }

                // Extract RuleGroups from EventFiltering
                if let Some(event_filtering) = obj.get("EventFiltering") {
                    if let Some(rule_groups) = event_filtering.get("RuleGroup") {
                        match rule_groups {
                            serde_json::Value::Array(arr) => {
                                for rg in arr {
                                    let value = convert_json_value(rg);
                                    self.current_rules.push(value);
                                }
                            }
                            _ => {
                                // Single RuleGroup
                                let value = convert_json_value(rule_groups);
                                self.current_rules.push(value);
                            }
                        }
                    }
                }
            }
            _ => return Err(ConversionError::InvalidFile("Not a JSON object".into())),
        }
        self.processed_files_count += 1;
        Ok(())
    }

    fn build_merged_config(&self) -> Result<Value, ConversionError> {
        let version = self.schema_version.clone().unwrap_or_else(|| "4.30".into());
    
        // Root object
        let mut root = HashMap::new();
        root.insert("@schemaversion".to_string(), Value::String(version));
    
        // Add EventFiltering with a single RuleGroup
        if !self.current_rules.is_empty() {
            let mut ef_map = HashMap::new();
            
            // Create a single RuleGroup that combines all rules
            let mut combined_rule_group = HashMap::new();
            combined_rule_group.insert("@name".to_string(), Value::String("MergedRules".to_string()));
            combined_rule_group.insert("@groupRelation".to_string(), Value::String("or".to_string()));
    
            // Collect all ProcessCreate rules
            let mut process_creates = Vec::new();
            for rule in &self.current_rules {
                if let Value::Object(rule_obj) = rule {
                    if let Some(process_create) = rule_obj.get("ProcessCreate") {
                        process_creates.push(process_create.clone());
                    }
                }
            }
    
            // Combine all ProcessCreate rules into a single rule
            if !process_creates.is_empty() {
                let mut combined_process_create = HashMap::new();
                combined_process_create.insert("@onmatch".to_string(), Value::String("include".to_string()));
                
                // Combine all Image conditions
                let mut images = Vec::new();
                for pc in process_creates {
                    if let Value::Object(pc_obj) = pc {
                        if let Some(image) = pc_obj.get("Image") {
                            images.push(image.clone());
                        }
                    }
                }
                
                combined_process_create.insert("Image".to_string(), Value::Array(images));
                combined_rule_group.insert("ProcessCreate".to_string(), Value::Object(combined_process_create));
            }
    
            ef_map.insert("RuleGroup".to_string(), Value::Object(combined_rule_group));
            root.insert("EventFiltering".to_string(), Value::Object(ef_map));
        }
    
        let merged_value = Value::Object(root);
    
        // Convert to XML for validation and validate immediately
        let mut writer = Writer::new(Vec::new());
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        write_xml_value(&mut writer, "Sysmon", &merged_value, "merged_config")?;
        let xml_content = String::from_utf8(writer.into_inner())
            .map_err(|e| ConversionError::InvalidFile(e.to_string()))?;
    
        // Validate the merged configuration
        let config = parse_sysmon_config_from_str(&xml_content)
            .map_err(|e| ConversionError::ValidationError(format!("Parse error: {}", e)))?;
        
        validate_sysmon_config(&config)
            .map_err(|e| ConversionError::ValidationError(format!("Validation error: {}", e)))?;
    
        Ok(merged_value)
    }

}

// Helper function to write XML
fn write_xml_value<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: &str,
    value: &Value,
    path: impl Into<PathBuf>,
) -> Result<(), ConversionError> {
    let path = path.into();
    
    match value {
        Value::Object(obj) => {
            let mut elem = BytesStart::new(name);
            
            // Write attributes
            for (key, value) in obj {
                if key.starts_with('@') {
                    if let Value::String(attr_value) = value {
                        elem.push_attribute((&key[1..], attr_value.as_str()));
                    }
                }
            }

            writer.write_event(Event::Start(elem.clone()))
                .map_err(|e| ConversionError::io_error(&path, e))?;

            // Write text content
            if let Some(Value::String(text)) = obj.get("$text") {
                writer.write_event(Event::Text(BytesText::new(text)))
                    .map_err(|e| ConversionError::io_error(&path, e))?;
            }

            // Write child elements
            for (key, value) in obj {
                if !key.starts_with('$') && !key.starts_with('@') {
                    write_xml_value(writer, key, value, &path)?;
                }
            }

            writer.write_event(Event::End(elem.to_end()))
                .map_err(|e| ConversionError::io_error(&path, e))?;
        },
        Value::Array(arr) => {
            for value in arr {
                write_xml_value(writer, name, value, &path)?;
            }
        },
        Value::String(s) => {
            let elem = BytesStart::new(name);
            writer.write_event(Event::Start(elem.clone()))
                .map_err(|e| ConversionError::io_error(&path, e))?;
            writer.write_event(Event::Text(BytesText::new(s)))
                .map_err(|e| ConversionError::io_error(&path, e))?;
            writer.write_event(Event::End(elem.to_end()))
                .map_err(|e| ConversionError::io_error(&path, e))?;
        },
        Value::Number(n) => {
            let elem = BytesStart::new(name);
            writer.write_event(Event::Start(elem.clone()))
                .map_err(|e| ConversionError::io_error(&path, e))?;
            writer.write_event(Event::Text(BytesText::new(&n.to_string())))
                .map_err(|e| ConversionError::io_error(&path, e))?;
            writer.write_event(Event::End(elem.to_end()))
                .map_err(|e| ConversionError::io_error(&path, e))?;
        },
        Value::Bool(b) => {
            let elem = BytesStart::new(name);
            writer.write_event(Event::Start(elem.clone()))
                .map_err(|e| ConversionError::io_error(&path, e))?;
            writer.write_event(Event::Text(BytesText::new(&b.to_string())))
                .map_err(|e| ConversionError::io_error(&path, e))?;
            writer.write_event(Event::End(elem.to_end()))
                .map_err(|e| ConversionError::io_error(&path, e))?;
        },
        Value::Null => {
            writer.write_event(Event::Empty(BytesStart::new(name)))
                .map_err(|e| ConversionError::io_error(&path, e))?;
        },
    }
    Ok(())
}

fn convert_json_value(json_value: &serde_json::Value) -> Value {
    match json_value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => Value::Number(n.clone()),
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(convert_json_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut new_map = HashMap::new();
            for (k, v) in map {
                new_map.insert(k.clone(), convert_json_value(v));
            }
            Value::Object(new_map)
        }
    }
}

/// Public merge_configs function
pub fn merge_configs(
    input_dir: &Path,
    output_file: &Path,
    recursive: bool,
) -> Result<(), ConversionError> {
    let mut merger = ConfigMerger::new();
   
    // Add logging for input directory contents
    info!("Scanning directory: {}", input_dir.display());
    let files: Vec<_> = WalkDir::new(input_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    info!("Found {} files to process", files.len());

    // Process files and collect detailed errors
    let merged_config = match merger.merge_directory(input_dir, recursive) {
        Ok(config) => config,
        Err(e) => {
            error!("Merger error: {}", e);
            error!("Rules processed: {}", merger.current_rules_count());
            error!("Files processed: {}", merger.processed_files_count());
            if let Some(last_file) = merger.last_processed_file() {
                error!("Last processed file: {}", last_file.display());
            }
            return Err(e);
        }
    };

    // Log merged config details before writing
    info!(
        "Successfully merged {} rules from {} files",
        merger.current_rules_count(),
        merger.processed_files_count()
    );
   
    // Write and validate output
    match output_file.extension().and_then(|ext| ext.to_str()) {
        Some("json") => {
            let json_str = serde_json::to_string_pretty(&merged_config)?;
            std::fs::write(output_file, json_str)
                .map_err(|e| ConversionError::io_error(output_file, e))?;
        }
        Some("xml") => {
            let mut writer = Writer::new(Vec::new());
            writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
                .map_err(|e| ConversionError::io_error(output_file, e))?;
            write_xml_value(&mut writer, "Sysmon", &merged_config, output_file)?;
            let xml_content = writer.into_inner();
           
            // Validate before writing
            info!("Validating merged configuration...");
            match String::from_utf8(xml_content.clone()) {
                Ok(xml_str) => {
                    let config = parse_sysmon_config_from_str(&xml_str)?;
                    if let Err(e) = validate_sysmon_config(&config) {
                        error!("Validation failed for merged config:");
                        error!("Rule count: {}", merger.current_rules_count());
                        error!("Config schema version: {:?}", merger.schema_version);
                        error!("Generated XML:\n{}", xml_str);
                        return Err(e.into());
                    }
                }
                Err(e) => return Err(ConversionError::InvalidFile(format!("Invalid UTF-8: {}", e))),
            }
           
            std::fs::write(output_file, xml_content)
                .map_err(|e| ConversionError::io_error(output_file, e))?;
        }
        _ => return Err(ConversionError::InvalidFile("Invalid output extension".into())),
    }
    Ok(())
}

pub fn merge_configs_with_progress(
    input_dir: &Path,
    output_file: &Path,
    recursive: bool,
    progress: &ProgressReporter,
) -> Result<(), ConversionError> {
    let mut merger = ConfigMerger::new();
    let walker = if recursive {
        WalkDir::new(input_dir)
    } else {
        WalkDir::new(input_dir).max_depth(1)
    };

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase());

        match ext.as_deref() {
            Some("xml") => {
                info!("Processing XML file: {:?}", path);
                let content = std::fs::read_to_string(path)
                    .map_err(|e| ConversionError::io_error(path, e))?;
                let _config = parse_sysmon_config_from_str(&content)?;
                merger.process_xml_file(path)?;
                progress.increment();
            }
            Some("json") => {
                info!("Processing JSON file: {:?}", path);
                let content = std::fs::read_to_string(path)
                    .map_err(|e| ConversionError::io_error(path, e))?;
                let json_value: serde_json::Value = serde_json::from_str(&content)?;
                merger.process_json_value(json_value)?;
                progress.increment();
            }
            _ => continue,
        }
    }

    let merged_config = merger.build_merged_config()?;

    // Write output based on extension
    match output_file.extension().and_then(|ext| ext.to_str()) {
        Some("json") => {
            let json_str = serde_json::to_string_pretty(&merged_config)?;
            std::fs::write(output_file, json_str)
                .map_err(|e| ConversionError::io_error(output_file, e))?;
        }
        Some("xml") => {
            let mut writer = Writer::new(Vec::new());
            writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
                .map_err(|e| ConversionError::io_error(output_file, e))?;
            write_xml_value(&mut writer, "Sysmon", &merged_config, output_file)?;
            std::fs::write(output_file, writer.into_inner())
                .map_err(|e| ConversionError::io_error(output_file, e))?;
        }
        _ => return Err(ConversionError::InvalidFile("Invalid output extension".into())),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use crate::error::ConversionError;

    #[test]
    fn test_merge_json_configs() {
        let temp_dir = tempdir().unwrap();
    
        let json1 = r#"{
            "@schemaversion": "4.30",
            "EventFiltering": {
                "RuleGroup": {
                    "@name": "test1",
                    "@groupRelation": "or",
                    "ProcessCreate": {
                        "@onmatch": "include",
                        "Image": {
                            "@condition": "is",
                            "$text": "C:\\Windows\\System32\\test1.exe"
                        }
                    }
                }
            }
        }"#;
    
        let json2 = r#"{
            "@schemaversion": "4.30",
            "EventFiltering": {
                "RuleGroup": {
                    "@name": "test2",
                    "@groupRelation": "or",
                    "ProcessCreate": {
                        "@onmatch": "include",
                        "Image": {
                            "@condition": "is",
                            "$text": "C:\\Windows\\System32\\test2.exe"
                        }
                    }
                }
            }
        }"#;
    
        fs::write(temp_dir.path().join("config1.json"), json1).unwrap();
        fs::write(temp_dir.path().join("config2.json"), json2).unwrap();
    
        let output_file = temp_dir.path().join("merged.json");
        let result = merge_configs(temp_dir.path(), &output_file, false);
        assert!(result.is_ok());
    
        if result.is_ok() {
            let merged_content = fs::read_to_string(&output_file).unwrap();
            assert!(merged_content.contains("test1.exe"));
            assert!(merged_content.contains("test2.exe"));
            assert!(merged_content.contains("MergedRules"));
        }
    }
    
    #[test]
    fn test_merge_xml_configs() {
        let temp_dir = tempdir().unwrap();
    
        let xml1 = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="test1" groupRelation="or">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\test1.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
    
        let xml2 = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="test2" groupRelation="or">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\test2.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
    
        fs::write(temp_dir.path().join("config1.xml"), xml1).unwrap();
        fs::write(temp_dir.path().join("config2.xml"), xml2).unwrap();
    
        let output_file = temp_dir.path().join("merged.xml");
        let result = merge_configs(temp_dir.path(), &output_file, false);
        assert!(result.is_ok());
    
        if result.is_ok() {
            let merged_content = fs::read_to_string(&output_file).unwrap();
            assert!(merged_content.contains("test1.exe"));
            assert!(merged_content.contains("test2.exe"));
            assert!(merged_content.contains("MergedRules"));
        }
    }
    
    #[test]
    fn test_merge_mixed_configs() {
        let temp_dir = tempdir().unwrap();
    
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="test1" groupRelation="or">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\test1.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
    
        let json = r#"{
            "@schemaversion": "4.30",
            "EventFiltering": {
                "RuleGroup": {
                    "@name": "test2",
                    "@groupRelation": "or",
                    "ProcessCreate": {
                        "@onmatch": "include",
                        "Image": {
                            "@condition": "is",
                            "$text": "C:\\Windows\\System32\\test2.exe"
                        }
                    }
                }
            }
        }"#;
    
        fs::write(temp_dir.path().join("config1.xml"), xml).unwrap();
        fs::write(temp_dir.path().join("config2.json"), json).unwrap();
    
        let output_xml = temp_dir.path().join("merged.xml");
        let result_xml = merge_configs(temp_dir.path(), &output_xml, false);
        assert!(result_xml.is_ok());
        
        let merged_xml = fs::read_to_string(&output_xml).unwrap();
        assert!(merged_xml.contains("test1.exe"));
        assert!(merged_xml.contains("test2.exe"));
    
        let output_json = temp_dir.path().join("merged.json");
        let result_json = merge_configs(temp_dir.path(), &output_json, false);
        assert!(result_json.is_ok());
    
        let merged_json = fs::read_to_string(&output_json).unwrap();
        assert!(merged_json.contains("test1.exe"));
        assert!(merged_json.contains("test2.exe"));
    }

    #[test]
    fn test_merge_invalid_configs() {
        let temp_dir = tempdir().unwrap();
    
        // This config has an invalid condition that should definitely fail validation
        let xml1 = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="test1" groupRelation="or">
                        <ProcessCreate onmatch="invalid_match_type">  <!-- invalid onmatch value -->
                            <Image condition="is">test1.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
    
        // Second config is valid
        let xml2 = r#"<?xml version="1.0" encoding="UTF-8"?>
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="test2" groupRelation="or">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">test2.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
    
        fs::write(temp_dir.path().join("config1.xml"), xml1).unwrap();
        fs::write(temp_dir.path().join("config2.xml"), xml2).unwrap();
    
        let output_file = temp_dir.path().join("merged.xml");
        let result = merge_configs(temp_dir.path(), &output_file, false);
    
        match result {
            Err(ConversionError::ValidationError(_)) => (),
            Err(e) => panic!("Expected ValidationError, got: {:?}", e),
            Ok(_) => panic!("Expected validation to fail, but it succeeded"),
        }
    }
}