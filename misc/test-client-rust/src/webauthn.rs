use serde_json::Value;
use std::collections::HashMap;
use tiny_http::{Header, Method, Response, Server};

use crate::{CliArgs, util::{make_request, verbose_log}};

fn handle_incoming_requests(server: Server, registration_request: &Value) -> Value {
    for mut request in server.incoming_requests() {
        let path = request.url();
        let method = request.method();

        match (method, path) {
            (Method::Get, "/") => {
                let html = include_bytes!("../assets/webauthn.html");
                let response = Response::from_data(html)
                    .with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                            .unwrap(),
                    );
                request.respond(response).expect("Failed to send HTML response");
            }
            (Method::Get, "/request") => {
                let json = serde_json::to_vec(registration_request).unwrap();
                let response = Response::from_data(json)
                    .with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap(),
                    );
                request.respond(response).expect("Failed to send registration request");
            }
            (Method::Post, "/response") => {
                let mut content = Vec::new();
                if let Err(e) = request.as_reader().read_to_end(&mut content) {
                    eprintln!("Failed to read request body from page: {e}");
                    let response = Response::from_string("Error reading request").with_status_code(400);
                    request.respond(response).expect("Failed to send error response");
                    continue;
                }

                let payload: Value = match serde_json::from_slice(&content) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to parse JSON from page: {e}");
                        let response = Response::from_string("Invalid JSON").with_status_code(400);
                        request.respond(response).expect("Failed to send error response");
                        continue;
                    }
                };

                // Send 204 No Content response to browser
                let response = Response::empty(204);
                request.respond(response).expect("Failed to send success response");

                // Return the client's credential response
                return payload;
            }
            _ => {
                let response = Response::from_string("Not found").with_status_code(404);
                request.respond(response).expect("Failed to send 404 response");
            }
        }
    }

    panic!("Server closed without completing registration");
}

pub fn add_webauthn_credential(args: CliArgs) {
    let auth_token = args
        .token
        .as_ref()
        .expect("auth token is required for adding WebAuthn credential");

    let credential_name = args
        .add_webauthn_credential
        .clone()
        .expect("credential name is required");

    println!("Fetching registration request from server...");
    let (registration_request, status) = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/accounts/2fa/webauthn/init",
        Some(auth_token),
        None,
    );

    if status != reqwest::StatusCode::OK {
        eprintln!("Failed to get registration request");
        return;
    }

    // Extract registrationId and request from the init response
    let registration_id = registration_request
        .get("registrationId")
        .and_then(|v| v.as_str())
        .expect("registrationId field is required");

    verbose_log(&args, format!("registration id: {registration_id}").as_str());

    let credential_creation_options = registration_request
        .get("request")
        .expect("request field is required");

    verbose_log(&args, format!("credential creation options: {credential_creation_options:?}").as_str());

    let server_addr = format!("127.0.0.1:{}", args.webauthn_port);
    let server = Server::http(&server_addr)
        .unwrap_or_else(|_| panic!("Failed to bind to {}", server_addr));
    println!("WebAuthn server running on http://{}, opening browser...", server_addr);

    // Open browser in a separate thread
    let url = format!("http://localhost:{}/", args.webauthn_port);
    std::thread::spawn(move || {
        open::that(&url).expect("Failed to open browser");
    });

    // Handle requests and get the client credential response
    let credential_response = handle_incoming_requests(server, credential_creation_options);

    verbose_log(&args, format!("credential response: {credential_response:?}").as_str());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("registrationId", registration_id.into());
    body.insert("name", credential_name.into());
    body.insert("response", credential_response);

    // Make request to server to finalize registration
    println!("Finalizing WebAuthn registration...");
    let (resp, status) = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/accounts/2fa/webauthn/finalize",
        Some(auth_token),
        Some(body),
    );

    if status != reqwest::StatusCode::OK {
        eprintln!("Failed to finalize registration");
        return;
    }

    // Print recovery key if present
    if let Some(recovery_key) = resp.get("recoveryKey").and_then(|v| v.as_str()) {
        println!("Recovery key: {recovery_key}");
    }

    println!("WebAuthn credential added successfully");
}
