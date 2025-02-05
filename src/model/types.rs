use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Generic Value type for XML/JSON conversion
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

// Sysmon-specific types module
pub mod sysmon {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SysmonConfig {
        #[serde(rename = "@schemaversion")]
        pub schema_version: String,
        #[serde(rename = "EventFiltering")]
        pub event_filtering: Option<EventFiltering>,
        pub hash_algorithms: Option<String>,
        pub check_revocation: Option<bool>,
        pub dns_lookup: Option<bool>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct EventFiltering {
        #[serde(rename = "RuleGroup")]
        pub rule_groups: Vec<RuleGroup>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct RuleGroup {
        #[serde(rename = "@name")]
        pub name: String,
        #[serde(rename = "@groupRelation")]
        pub group_relation: String,
        #[serde(flatten)]
        pub events: HashMap<String, EventRules>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct EventRules {
        #[serde(rename = "@onmatch")]
        pub onmatch: String,
        #[serde(flatten)]
        pub rules: HashMap<String, Vec<Rule>>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Rule {
        #[serde(rename = "@condition")]
        pub condition: String,
        #[serde(rename = "$text")]
        pub value: String,
    }
}

// Re-export SysmonConfig for convenience
pub use self::sysmon::SysmonConfig;