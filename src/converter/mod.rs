use crate::error::ConversionError;
use std::path::Path;

pub mod xml;
pub mod json;

pub trait Converter {
    fn convert(&self, input: &Path, output: &Path) -> Result<(), ConversionError>;
}

pub struct XmlToJson;
pub struct JsonToXml;

impl XmlToJson {
    pub fn new() -> Self {
        Self
    }
}

impl JsonToXml {
    pub fn new() -> Self {
        Self
    }
}

pub fn get_converter(input: &Path, output: &Path) -> Result<Box<dyn Converter>, ConversionError> {
    let input_ext = input.extension()
        .and_then(|e| e.to_str())
        .ok_or_else(|| ConversionError::InvalidFile("Input file has no extension".into()))?
        .to_lowercase();

    let output_ext = output.extension()
        .and_then(|e| e.to_str())
        .ok_or_else(|| ConversionError::InvalidFile("Output file has no extension".into()))?
        .to_lowercase();

    match (input_ext.as_str(), output_ext.as_str()) {
        ("xml", "json") => Ok(Box::new(XmlToJson::new())),
        ("json", "xml") => Ok(Box::new(JsonToXml::new())),
        _ => Err(ConversionError::InvalidFile(
            format!("Unsupported conversion: {} to {}", input_ext, output_ext)
        )),
    }
}