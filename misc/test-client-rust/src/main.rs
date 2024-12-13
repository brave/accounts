use argon2::Argon2;
use clap::{CommandFactory, Parser};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand::rngs::OsRng;
use serde_json::Value;
use std::collections::HashMap;

#[allow(dead_code)]
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = Argon2<'static>;
}

/// Brave Accounts test client
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct CliArgs {
    /// Base URL for the API
    #[arg(long, default_value = "http://localhost:8080")]
    base_url: String,

    /// User's email address
    #[arg(long)]
    email: String,

    /// User's password (only required for password setting and authentication)
    #[arg(long)]
    password: Option<String>,

    /// Verification token (optional)
    #[arg(long)]
    token: Option<String>,

    /// Verify intent (optional)
    #[arg(long)]
    verify_intent: Option<String>,

    /// Verify service (optional)
    #[arg(long)]
    verify_service: Option<String>,

    /// Set brave-services-key header
    #[arg(short = 'k', long)]
    services_key: Option<String>,

    /// Login mode flag
    #[arg(short, long)]
    login: bool,

    /// Register mode flag
    #[arg(short, long)]
    register: bool,

    /// Set password mode flag
    #[arg(short, long)]
    set_password: bool,

    /// Email auth flag
    #[arg(short = 'e', long)]
    email_auth: bool,

    /// Email verify flag
    #[arg(long)]
    email_verify: bool,
}

fn make_request(
    args: &CliArgs,
    method: reqwest::Method,
    path: &str,
    bearer_token: Option<&str>,
    body: Option<HashMap<&str, Value>>,
) -> HashMap<String, Value> {
    // add user agent of some sort.
    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .build()
        .expect("Failed to create HTTP client");
    let mut request_builder = client.request(method, args.base_url.clone() + path);

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

    response
        .json::<HashMap<String, Value>>()
        .expect("Failed to parse response as HashMap<String, Value>")
}

fn display_account_details(args: &CliArgs, auth_token: &str) {
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
}

fn verify(args: &CliArgs) -> (String, Option<String>) {
    let mut body = HashMap::new();
    body.insert(
        "service",
        Value::String(
            if let Some(service) = args.verify_service.as_ref() {
                service.as_str()
            } else if args.email_auth || args.email_verify {
                "email-aliases"
            } else {
                "accounts"
            }
            .to_string(),
        ),
    );
    body.insert(
        "intent",
        Value::String(
            if let Some(intent) = args.verify_intent.as_ref() {
                intent.as_str()
            } else if args.email_verify {
                "verification"
            } else if args.email_auth {
                "auth_token"
            } else if args.set_password {
                "set_password"
            } else {
                "registration"
            }
            .to_string(),
        ),
    );

    body.insert("email", Value::String(args.email.clone()));

    let init_response = make_request(
        args,
        reqwest::Method::POST,
        "/v2/verify/init",
        None,
        Some(body),
    );
    let verification_token = init_response
        .get("verificationToken")
        .and_then(|v| v.as_str())
        .expect("Failed to get verification token");

    println!("Click on the verification link...");

    loop {
        let mut result_body = HashMap::new();
        result_body.insert("wait", true.into());

        let result = make_request(
            args,
            reqwest::Method::POST,
            "/v2/verify/result",
            Some(verification_token),
            Some(result_body),
        );

        if result
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let auth_token = result
                .get("authToken")
                .and_then(|v| v.as_str())
                .map(String::from);
            println!("verification token: {}", verification_token);
            return (verification_token.to_string(), auth_token);
        }
    }
}

fn set_password(args: CliArgs) {
    let token = match &args.token {
        Some(t) => t.trim().to_string(),
        None => verify(&args).0,
    };

    let mut client_rng = OsRng;

    let password = args
        .password
        .as_ref()
        .expect("password must be provided")
        .as_bytes();
    let registration_request =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password).unwrap();
    let registration_request_hex = hex::encode(registration_request.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("blindedMessage", registration_request_hex.into());
    body.insert("serializeResponse", true.into());

    let resp = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/accounts/password/init",
        Some(&token),
        Some(body),
    );

    let resp_bin = hex::decode(
        resp.get("serializedResponse")
            .and_then(|v| v.as_str())
            .expect("Missing serializedResponse field"),
    )
    .expect("Failed to decode hex");

    let finish_result = registration_request
        .state
        .finish(
            &mut client_rng,
            password,
            RegistrationResponse::deserialize(&resp_bin).unwrap(),
            ClientRegistrationFinishParameters {
                identifiers: Identifiers {
                    client: Some(args.email.as_bytes()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let record_hex = hex::encode(finish_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("serializedRecord", record_hex.into());

    let resp = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/accounts/password/finalize",
        Some(&token),
        Some(body),
    );

    display_account_details(&args, resp.get("authToken").unwrap().as_str().unwrap());
}

fn login(args: CliArgs) {
    let mut client_rng = OsRng;
    let password = args
        .password
        .as_ref()
        .expect("password must be provided")
        .as_bytes();
    let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, password).unwrap();

    let credential_request_hex = hex::encode(client_login_start_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("serializedKE1", credential_request_hex.into());
    body.insert("email", args.email.clone().into());

    let resp = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/auth/login/init",
        None,
        Some(body),
    );

    let ke2_bin = hex::decode(
        resp.get("serializedKE2")
            .and_then(|v| v.as_str())
            .expect("Missing serializedKE2 field"),
    )
    .expect("Failed to decode hex");

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            password,
            CredentialResponse::deserialize(&ke2_bin).unwrap(),
            ClientLoginFinishParameters {
                identifiers: Identifiers {
                    client: Some(args.email.as_bytes()),
                    server: None,
                },
                ..Default::default()
            },
        )
        .unwrap();

    let credential_finalization_hex = hex::encode(client_login_finish_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("clientMac", credential_finalization_hex.into());

    let resp = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/auth/login/finalize",
        Some(
            resp.get("akeToken")
                .and_then(|v| v.as_str())
                .expect("Missing akeToken field"),
        ),
        Some(body),
    );

    display_account_details(&args, resp.get("authToken").unwrap().as_str().unwrap());
}

fn main() {
    let args = CliArgs::parse();

    if args.email_verify {
        verify(&args);
    } else if args.email_auth {
        let (_, auth_token) = verify(&args);
        display_account_details(&args, auth_token.unwrap_or_default().as_str());
    } else if args.login {
        login(args);
    } else if args.register || args.set_password {
        set_password(args);
    } else {
        CliArgs::command()
            .print_help()
            .expect("Failed to display help message");
        eprintln!("Must supply -l, -r, -s, -e or --email-verify");
        std::process::exit(1);
    }
}
