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

    /// User's password
    #[arg(long)]
    password: String,

    /// Verification token (if required)
    #[arg(long)]
    token: Option<String>,

    /// Login mode flag
    #[arg(short, long)]
    login: bool,

    /// Register mode flag
    #[arg(short, long)]
    register: bool,

    /// Set password mode flag
    #[arg(short, long)]
    set_password: bool,
}

fn post_request(
    args: &CliArgs,
    path: &str,
    bearer_token: Option<&str>,
    body: HashMap<&str, Value>,
) -> HashMap<String, Value> {
    // add user agent of some sort.
    let client = reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .build()
        .expect("Failed to create HTTP client");
    let mut request_builder = client.post(args.base_url.clone() + path).json(&body);

    // Add authorization header if bearer token is provided
    if let Some(token) = bearer_token {
        request_builder = request_builder.header("Authorization", format!("Bearer {}", token));
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

fn verify(args: &CliArgs) -> String {
    let mut body = HashMap::new();
    body.insert("service", Value::String("accounts".to_string()));
    body.insert(
        "intent",
        Value::String(
            if args.set_password {
                "set_password"
            } else {
                "registration"
            }
            .to_string(),
        ),
    );
    body.insert("email", Value::String(args.email.clone()));

    let init_response = post_request(args, "/v2/verify/init", None, body);
    let token = init_response
        .get("verificationToken")
        .and_then(|v| v.as_str())
        .expect("Failed to get verification token");

    println!("Click on the verification link...");

    loop {
        let mut result_body = HashMap::new();
        result_body.insert("wait", true.into());

        let result = post_request(args, "/v2/verify/result", Some(token), result_body);

        if result
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return token.to_string();
        }
    }
}

fn set_password(args: CliArgs) {
    let token = match &args.token {
        Some(t) => t.trim().to_string(),
        None => verify(&args),
    };

    let mut client_rng = OsRng;

    let registration_request =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, args.password.as_bytes())
            .unwrap();
    let registration_request_hex = hex::encode(registration_request.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("blindedMessage", registration_request_hex.into());
    body.insert("serializeResponse", true.into());

    let resp = post_request(&args, "/v2/accounts/password/init", Some(&token), body);

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
            args.password.as_bytes(),
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

    let resp = post_request(&args, "/v2/accounts/password/finalize", Some(&token), body);

    println!(
        "auth token: {}",
        resp.get("authToken").unwrap().as_str().unwrap()
    )
}

fn login(args: CliArgs) {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, args.password.as_bytes())
            .unwrap();

    let credential_request_hex = hex::encode(client_login_start_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("serializedKE1", credential_request_hex.into());
    body.insert("email", args.email.clone().into());

    let resp = post_request(&args, "/v2/auth/login/init", None, body);

    let ke2_bin = hex::decode(
        resp.get("serializedKE2")
            .and_then(|v| v.as_str())
            .expect("Missing serializedKE2 field"),
    )
    .expect("Failed to decode hex");

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            args.password.as_bytes(),
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

    let resp = post_request(
        &args,
        "/v2/auth/login/finalize",
        Some(
            resp.get("akeToken")
                .and_then(|v| v.as_str())
                .expect("Missing akeToken field"),
        ),
        body,
    );

    println!(
        "auth token: {}",
        resp.get("authToken").unwrap().as_str().unwrap()
    )
}

fn main() {
    let args = CliArgs::parse();

    if args.login {
        login(args);
    } else if args.register || args.set_password {
        set_password(args);
    } else {
        CliArgs::command()
            .print_help()
            .expect("Failed to display help message");
        eprintln!("Must supply -l, -r or -s");
        std::process::exit(1);
    }
}
