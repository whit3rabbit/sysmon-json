use std::fs;
use std::path::Path;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde_json::{Value, Map};
use crate::error::ConversionError;
use crate::converter::{XmlToJson, Converter};
use sysmon_validator::{parse_sysmon_config_from_str, validate_sysmon_config};
use log::info;

impl Converter for XmlToJson {
    fn convert(&self, input: &Path, output: &Path) -> Result<(), ConversionError> {
        // Read the XML content
        let xml_content = fs::read_to_string(input)?;
        
        // Validate the Sysmon configuration before converting
        info!("Validating Sysmon configuration before conversion");
        let config = parse_sysmon_config_from_str(&xml_content)?;
        validate_sysmon_config(&config)?;
        
        // If validation passes, proceed with conversion
        info!("Validation successful, proceeding with conversion");
        let value = xml_to_value(&xml_content)?;
        let json_string = serde_json::to_string_pretty(&value)?;
        fs::write(output, json_string)?;
        
        Ok(())
    }
}

fn xml_to_value(xml: &str) -> Result<Value, ConversionError> {
    let mut reader = Reader::from_str(xml);
    
    match read_next_value(&mut reader) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Ok(Value::Null),
        Err(e) => Err(e),
    }
}

fn read_next_value(reader: &mut Reader<&[u8]>) -> Result<Option<Value>, ConversionError> {
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let mut obj = Map::new();

                // Handle attributes
                for attr in e.attributes().flatten() {
                    let key = format!("@{}", String::from_utf8_lossy(attr.key.as_ref()));
                    let value = String::from_utf8_lossy(&attr.value).into_owned();
                    obj.insert(key, Value::String(value));
                }

                // Handle child elements
                let mut text_content = String::new();
                let mut children = Map::new(); // Changed from Vec<Value> to Map<String, Value>

                loop {
                    match reader.read_event_into(&mut buf) {
                        Ok(Event::Start(ref child)) => {
                            let child_name = String::from_utf8_lossy(child.name().as_ref()).into_owned();
                            if let Some(child_value) = read_next_value(reader)? {
                                children.insert(child_name, child_value);
                            }
                        },
                        Ok(Event::Text(e)) => {
                            text_content.push_str(&e.unescape().map_err(|e| 
                                ConversionError::XmlParse(quick_xml::DeError::InvalidXml(e)))?);
                        },
                        Ok(Event::End(ref e)) if e.name().as_ref() == e.name().as_ref() => {
                            break;
                        },
                        Ok(Event::Eof) => break,
                        Err(e) => return Err(ConversionError::XmlParse(
                            quick_xml::DeError::InvalidXml(e))),
                        _ => {},
                    }
                    buf.clear();
                }

                // Handle the content
                if !text_content.trim().is_empty() {
                    obj.insert("$text".to_string(), Value::String(text_content.trim().to_string()));
                }

                // Merge children into obj
                if !children.is_empty() {
                    obj.extend(children);
                }

                // Return the object with the element name
                let mut element = Map::new();
                element.insert(name, Value::Object(obj));
                return Ok(Some(Value::Object(element)));
            },
            Ok(Event::Text(e)) => {
                let text = e.unescape().map_err(|e| 
                    ConversionError::XmlParse(quick_xml::DeError::InvalidXml(e)))?.into_owned();
                if !text.trim().is_empty() {
                    return Ok(Some(Value::String(text.trim().to_string())));
                }
            },
            Ok(Event::Eof) => return Ok(None),
            Err(e) => return Err(ConversionError::XmlParse(
                quick_xml::DeError::InvalidXml(e))),
            _ => {}
        }
        buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_valid_sysmon_conversion() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("valid.xml");
        let output_path = temp_dir.path().join("output.json");
    
        let valid_xml = r#"
            <Sysmon schemaversion="4.30">
                <EventFiltering>
                    <RuleGroup name="test" groupRelation="or">
                        <ProcessCreate onmatch="include">
                            <Image condition="is">C:\Windows\System32\test.exe</Image>
                        </ProcessCreate>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;
    
        fs::write(&input_path, valid_xml).unwrap();
        
        let converter = XmlToJson::new();
        let result = converter.convert(&input_path, &output_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_sysmon_conversion() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("invalid.xml");
        let output_path = temp_dir.path().join("output.json");

        let invalid_xml = r#"
            <Sysmon schemaversion="3.50">
                <EventFiltering>
                    <RuleGroup name="test">
                        <InvalidEventType onmatch="include">
                            <Image condition="invalid_operator">test.exe</Image>
                        </InvalidEventType>
                    </RuleGroup>
                </EventFiltering>
            </Sysmon>"#;

        fs::write(&input_path, invalid_xml).unwrap();
        
        let converter = XmlToJson::new();
        let result = converter.convert(&input_path, &output_path);
        assert!(matches!(result, Err(ConversionError::ValidationError(_))));
    }
}