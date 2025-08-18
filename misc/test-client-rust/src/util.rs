use reqwest::StatusCode;
use serde_json::Value;
use std::{collections::HashMap, io::Write};

use crate::CliArgs;

// Type alias for response data
pub type Response = HashMap<String, Value>;

pub fn verbose_log(cli_args: &CliArgs, message: &str) {
    if cli_args.verbose {
        println!("{}", message);
    }
}

pub fn make_request(
    args: &CliArgs,
    method: reqwest::Method,
    path: &str,
    bearer_token: Option<&str>,
    body: Option<HashMap<&str, Value>>,
) -> Response {
    // add user agent of some sort.
    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .build()
        .expect("Failed to create HTTP client");
    let mut request_builder = client.request(method, args.base_url.clone() + path);

    verbose_log(&args, format!("request to {}: {:?}", path, body).as_str());
    if let Some(body) = body {
        request_builder = request_builder.json(&body);
    }

    // Add authorization header if bearer token is provided
    if let Some(token) = bearer_token {
        request_builder = request_builder.header("Authorization", format!("Bearer {}", token));
    }
    if let Some(key) = args.services_key.as_ref() {
        request_builder = request_builder.header("brave-key", key)
    }

    let response = request_builder.send().expect("Failed to send request");

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().unwrap();
        panic!(
            "Request failed with status: {}, body: {}",
            status, error_body
        );
    }

    if response.status() == StatusCode::NO_CONTENT {
        return HashMap::new();
    }

    let response_fields = response
        .json::<Response>()
        .expect("Failed to parse response as HashMap<String, Value>");

    verbose_log(&args, format!("response: {:?}", response_fields).as_str());

    response_fields
}

pub fn display_account_details(args: &CliArgs, auth_token: &str) {
    // Call validate endpoint
    let response = make_request(
        args,
        reqwest::Method::GET,
        "/v2/auth/validate",
        Some(auth_token),
        None,
    );

    println!("auth token: {}", auth_token);
    // Print accountId and sessionId
    println!(
        "account id: {}",
        response
            .get("accountId")
            .expect("account id should be in validate response")
            .as_str()
            .expect("account id should be a string")
    );

    println!(
        "session id: {}",
        response
            .get("sessionId")
            .expect("session id should be in validate response")
            .as_str()
            .expect("session id should be a string")
    );

    println!(
        "email: {}",
        response
            .get("email")
            .expect("email should be in validate response")
            .as_str()
            .expect("email should be a string")
    );

    println!(
        "service: {}",
        response
            .get("service")
            .expect("service should be in validate response")
            .as_str()
            .expect("service should be a string")
    );
}

pub fn prompt_for_input(prompt: &str) -> String {
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}
