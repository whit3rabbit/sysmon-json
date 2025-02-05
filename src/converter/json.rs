use std::fs;
use std::path::Path;
use quick_xml::{Writer, events::{Event, BytesStart, BytesEnd, BytesText}};
use std::io::Cursor;
use serde_json::Value;
use crate::error::ConversionError;
use crate::converter::{JsonToXml, Converter};

impl Converter for JsonToXml {
    fn convert(&self, input: &Path, output: &Path) -> Result<(), ConversionError> {
        let json_content = fs::read_to_string(input)?;
        let value: Value = serde_json::from_str(&json_content)?;
        let xml_string = value_to_xml(&value)?;
        fs::write(output, xml_string)?;
        Ok(())
    }
}

pub fn value_to_xml(value: &Value) -> Result<String, ConversionError> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    write_value(&mut writer, None, value)?;
    let result = String::from_utf8(writer.into_inner().into_inner())
        .map_err(|e| ConversionError::InvalidFile(e.to_string()))?;
    Ok(result)
}

fn write_value<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: Option<&str>,
    value: &Value,
) -> Result<(), ConversionError> {
    match value {
        Value::Object(map) => {
            let tag_name = name.unwrap_or("root"); // Use provided name or default to "root"
            let mut elem = BytesStart::new(tag_name);

            // Write attributes first
            for (key, value) in map.iter() {
                if key.starts_with('@') {
                    if let Value::String(attr_value) = value {
                        elem.push_attribute((&key[1..], attr_value.as_str()));
                    }
                }
            }

            writer.write_event(Event::Start(elem))?;

            // Write text content if it exists
            if let Some(Value::String(text)) = map.get("$text") {
                writer.write_event(Event::Text(BytesText::new(text)))?;
            }

            // Write child elements
            if let Some(Value::Array(children)) = map.get("$children") {
                for child in children {
                    write_value(writer, None, child)?;
                }
            }

            // Write regular elements (non-attributes, non-special)
            for (key, value) in map.iter() {
                if !key.starts_with('$') && !key.starts_with('@') {
                    write_value(writer, Some(key), value)?;
                }
            }

            writer.write_event(Event::End(BytesEnd::new(tag_name)))?;
        },
        Value::Array(arr) => {
            for value in arr {
                write_value(writer, name, value)?;
            }
        },
        Value::String(s) => {
            if let Some(tag_name) = name {
                writer.write_event(Event::Start(BytesStart::new(tag_name)))?;
                writer.write_event(Event::Text(BytesText::new(s)))?;
                writer.write_event(Event::End(BytesEnd::new(tag_name)))?;
            } else {
                writer.write_event(Event::Text(BytesText::new(s)))?;
            }
        },
        Value::Number(n) => {
            if let Some(tag_name) = name {
                writer.write_event(Event::Start(BytesStart::new(tag_name)))?;
                writer.write_event(Event::Text(BytesText::new(&n.to_string())))?;
                writer.write_event(Event::End(BytesEnd::new(tag_name)))?;
            } else {
                writer.write_event(Event::Text(BytesText::new(&n.to_string())))?;
            }
        },
        Value::Bool(b) => {
            if let Some(tag_name) = name {
                writer.write_event(Event::Start(BytesStart::new(tag_name)))?;
                writer.write_event(Event::Text(BytesText::new(&b.to_string())))?;
                writer.write_event(Event::End(BytesEnd::new(tag_name)))?;
            } else {
                writer.write_event(Event::Text(BytesText::new(&b.to_string())))?;
            }
        },
        Value::Null => {
            if let Some(tag_name) = name {
                writer.write_event(Event::Empty(BytesStart::new(tag_name)))?;
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simple_conversion() {
        let value = json!({
            "@version": "1.0",
            "$text": "content"
        });
        
        let xml = value_to_xml(&value).unwrap();
        assert!(xml.contains("version=\"1.0\""));
        assert!(xml.contains(">content<"));
    }
}