use serde_json::Value;

#[test]
fn openapi_covers_all_router_endpoints_and_references_are_valid() {
    let document: Value = serde_json::from_str(include_str!("../openapi.json")).unwrap();
    let paths = document["paths"].as_object().expect("OpenAPI paths object");
    let router = include_str!("../src/lib.rs");
    let mut counted = 0usize;

    for route in router.split(".route(").skip(1) {
        let Some(path) = route.split('"').nth(1) else {
            panic!("route missing a literal path");
        };
        assert!(
            paths.contains_key(path),
            "router path missing from OpenAPI: {path}"
        );
        counted += 1;
    }
    assert!(counted >= 16, "unexpectedly incomplete public router");
    assert_eq!(
        counted,
        paths.len(),
        "OpenAPI contains stale or invented routes"
    );

    for (path, methods) in paths {
        let methods = methods.as_object().expect("path methods object");
        for (method, definition) in methods {
            assert!(
                definition["responses"]
                    .as_object()
                    .is_some_and(|r| !r.is_empty()),
                "endpoint {method} {path} has no response contract"
            );
        }
    }

    fn validate_references(value: &Value, document: &Value) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if key == "$ref" {
                        let reference = child.as_str().expect("reference is a string");
                        let pointer = reference.strip_prefix('#').expect("local schema reference");
                        assert!(
                            document.pointer(pointer).is_some(),
                            "broken reference: {reference}"
                        );
                    } else {
                        validate_references(child, document);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    validate_references(item, document);
                }
            }
            _ => {}
        }
    }
    validate_references(&document, &document);
}
