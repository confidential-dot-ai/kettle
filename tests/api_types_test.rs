use kettle::api::{BuildRequest, Event};

#[test]
fn build_request_url_form_roundtrips_json() {
    let json = r#"{"nonce":"abcd","repo_url":"https://github.com/x/y","repo_ref":"main"}"#;
    let req: BuildRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.nonce, "abcd");
    assert_eq!(req.repo_url.as_deref(), Some("https://github.com/x/y"));
    assert_eq!(req.repo_ref.as_deref(), Some("main"));
    assert!(req.source_data.is_none());
}

#[test]
fn build_request_source_form_base64_roundtrips() {
    // 'PK\x03\x04' as base64 = UEsDBA==
    let json = r#"{"nonce":"00","source_data":"UEsDBA=="}"#;
    let req: BuildRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.source_data.as_deref(), Some(&[0x50u8, 0x4B, 0x03, 0x04][..]));
}

#[test]
fn event_serializes_with_tag() {
    let e = Event::Vm { msg: "hello".into() };
    let s = serde_json::to_string(&e).unwrap();
    assert_eq!(s, r#"{"type":"vm","msg":"hello"}"#);
}

#[test]
fn complete_event_failed_serializes() {
    let e = Event::Complete {
        result: kettle::api::BuildResult::Failed {
            error: "boom".into(),
            error_type: "BuildFailed".into(),
        },
    };
    let s = serde_json::to_string(&e).unwrap();
    assert!(s.contains(r#""type":"complete""#));
    assert!(s.contains(r#""status":"failed""#));
    assert!(s.contains(r#""error":"boom""#));
}
