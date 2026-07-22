use super::*;

#[test]
fn terminal_websocket_ticket_is_header_only_and_single_value() -> Result<(), String> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(
            "jw-terminal-v1, ticket.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    );
    let ticket =
        websocket_ticket(&headers).map_err(|_| String::from("valid terminal protocol rejected"))?;
    assert_eq!(ticket.len(), 43);

    headers.insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(
            "jw-terminal-v1, ticket.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, ticket.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        ),
    );
    assert!(websocket_ticket(&headers).is_err());
    Ok(())
}
