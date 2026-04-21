use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use mipsorcu::server::supabase::{SupabaseClient, SupabaseRpcError};

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

#[test]
fn supabase_error_display_does_not_expose_response_body() {
    let error = SupabaseRpcError::NonSuccessStatus {
        status: 400,
        body: "secret internal upstream details".to_owned(),
    };

    let rendered = error.to_string();

    assert!(rendered.contains("status 400"));
    assert!(rendered.contains("response body length"));
    assert!(!rendered.contains("secret internal upstream details"));
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_retries_with_publishable_key_after_unauthorized_head() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![401, 200]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let first_request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("first request should be captured");
    let second_request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("second request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(reachable);
    assert_eq!(first_request.method, "HEAD");
    assert_eq!(first_request.path, "/rest/v1/");
    assert!(!first_request.headers.contains_key("authorization"));
    assert!(!first_request.headers.contains_key("apikey"));

    assert_eq!(second_request.method, "HEAD");
    assert_eq!(second_request.path, "/rest/v1/");
    assert!(!second_request.headers.contains_key("authorization"));
    assert_eq!(
        second_request.headers.get("apikey"),
        Some(&"publishable-key".to_owned())
    );
    assert!(
        !second_request
            .headers
            .values()
            .any(|value| value.contains("service-role-secret"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_succeeds_without_auth_when_head_is_public() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![200]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(reachable);
    assert_eq!(request.method, "HEAD");
    assert_eq!(request.path, "/rest/v1/");
    assert!(!request.headers.contains_key("authorization"));
    assert!(!request.headers.contains_key("apikey"));
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_does_not_retry_on_non_auth_failure() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![404]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(!reachable);
    assert_eq!(request.method, "HEAD");
    assert_eq!(request.path, "/rest/v1/");
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );
}

fn spawn_probe_server(
    statuses: Vec<u16>,
) -> Result<
    (
        String,
        mpsc::Receiver<CapturedRequest>,
        thread::JoinHandle<std::io::Result<()>>,
    ),
    Box<dyn std::error::Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for status in statuses {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;
            write_http_response(&mut stream, status, "{}")?;
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    let header_end = loop {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before headers were complete",
            ));
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);

        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let request_line = headers.lines().next().unwrap_or_default();
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let headers = headers
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<HashMap<_, _>>();

    Ok(CapturedRequest {
        method,
        path,
        headers,
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}
