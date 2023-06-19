use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum Params {
    /// No parameters
    None,
    /// Array of values
    Array(Vec<Value>),
    /// Map of values
    Map(Map<String, Value>),
}

impl From<Params> for Value {
    fn from(params: Params) -> Value {
        match params {
            Params::Array(vec) => Value::Array(vec),
            Params::Map(map) => Value::Object(map),
            Params::None => Value::Null,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use rstest::rstest;

    fn expected_map() -> Map<String, Value> {
        let mut expected_map = serde_json::Map::new();
        expected_map.insert("key".to_string(), Value::String("value".to_string()));
        expected_map
    }

    #[rstest]
    #[case("[null]", Params::Array(vec![Value::Null]))]
    #[case("[true]", Params::Array(vec![Value::Bool(true)]))]
    #[case("[-1]", Params::Array(vec![Value::from(-1)]))]
    #[case("[4]", Params::Array(vec![Value::from(4)]))]
    #[case("[2.3]", Params::Array(vec![Value::from(2.3)]))]
    #[case("[\"hello\"]", Params::Array(vec![Value::String("hello".to_string())]))]
    #[case("[[0]]", Params::Array(vec![Value::Array(vec![Value::from(0)])]))]
    #[case("[[]]", Params::Array(vec![Value::Array(vec![])]))]
    #[case("[{\"key\": \"value\"}]", Params::Array(vec![Value::Object(expected_map())]))]
    #[case("[\"abc\",[0,256]]", 
        Params::Array(vec![
            Value::String("abc".to_string()),
            Value::Array(vec![
                Value::from(0),
                Value::from(256)
            ]),
        ])
    )]
    #[case("[[\"abc\", \"xyz\"],[256]]", 
        Params::Array(vec![
            Value::Array(vec![
                Value::String("abc".to_string()),
                Value::String("xyz".to_string())
            ]),
            Value::Array(vec![
                Value::from(256)
            ]),
        ])
    )]
    fn request_params_deserialization(#[case] input: &str, #[case] expected: Params) {
        let deserialized: Params = serde_json::from_str(input).unwrap();
        assert_eq!(deserialized, expected);
    }
}
