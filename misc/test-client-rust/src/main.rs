mod util;

use argon2::Argon2;
use clap::{CommandFactory, Parser};
use opaque_ke::{
    errors::ProtocolError, CipherSuite, ClientLogin, ClientLoginFinishParameters,
    ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, Identifiers,
    RegistrationResponse,
};
use rand::rngs::OsRng;
use serde_json::Value;
use std::{collections::HashMap, thread};
use totp_rs::TOTP;
use util::*;

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
    email: Option<String>,

    /// User's password (only required for password setting and authentication)
    #[arg(long)]
    password: Option<String>,

    /// Auth token
    #[arg(long)]
    token: Option<String>,

    /// Verify intent (optional)
    #[arg(long)]
    verify_intent: Option<String>,

    /// Service name (optional)
    #[arg(long)]
    service_name: Option<String>,

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
    #[arg(long)]
    reset_password: bool,

    /// Change password mode flag
    #[arg(short, long)]
    change_password: bool,

    /// Email auth flag
    #[arg(short = 'e', long)]
    email_auth: bool,

    /// Email verify flag
    #[arg(long)]
    email_verify: bool,

    /// Service token flag
    #[arg(short = 't', long)]
    create_service_token: bool,

    /// Verbose flag
    #[arg(short, long)]
    verbose: bool,

    /// Enable TOTP flag
    #[arg(long)]
    enable_totp: bool,

    /// TOTP URI for 2FA login
    #[arg(long)]
    totp_uri: Option<String>,

    /// Two-factor authentication recovery key
    #[arg(long)]
    twofa_recovery_key: Option<String>,
}

fn maybe_handle_twofa(args: &CliArgs, resp: Response, token: &str, endpoint: &str) -> Response {
    // If 2FA not required, just return the original response
    if !resp
        .get("requiresTwoFA")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return resp;
    }

    verbose_log(&args, "Two-factor authentication is required");

    let mut twofa_body: HashMap<&str, Value> = HashMap::new();
    if let Some(recovery_key) = args.twofa_recovery_key.as_ref() {
        twofa_body.insert("recoveryKey", recovery_key.as_str().into());
    } else {
        // Try to generate TOTP code if URI is provided
        let totp_code = if let Some(totp_uri) = args.totp_uri.as_ref() {
            let totp = TOTP::from_url(totp_uri).expect("Failed to parse TOTP URL");
            let code = totp
                .generate_current()
                .expect("Failed to generate TOTP code");
            verbose_log(&args, format!("Generated TOTP code: {}", code).as_str());
            code
        } else {
            // Prompt user for code
            prompt_for_input("Enter your 6-digit TOTP code: ")
        };
        twofa_body.insert("totpCode", totp_code.into());
    }

    make_request(
        args,
        reqwest::Method::POST,
        endpoint,
        Some(token),
        Some(twofa_body),
    )
}

fn wait_for_verification(args: &CliArgs, verification_token: &str) -> Option<String> {
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
            let email = result
                .get("email")
                .expect("email should be in result response")
                .as_str()
                .expect("email should be a string");
            let service_name = result
                .get("service")
                .expect("service should be in result response")
                .as_str()
                .expect("service should be a string");
            println!("verification token: {}", verification_token);
            println!("email: {}", email);
            println!("service: {}", service_name);
            return auth_token;
        }
    }
}

fn verify(args: &CliArgs) -> (String, Option<String>) {
    let mut body = HashMap::new();
    body.insert(
        "service",
        Value::String(
            if let Some(service) = args.service_name.as_ref() {
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
            } else if args.reset_password {
                "reset_password"
            } else if args.change_password {
                "change_password"
            } else {
                "registration"
            }
            .to_string(),
        ),
    );

    body.insert(
        "email",
        Value::String(args.email.as_ref().expect("email must be provided").clone()),
    );

    let auth_token = if args.change_password {
        Some(
            args.token
                .as_ref()
                .expect("auth token is required for password change")
                .trim(),
        )
    } else {
        None
    };

    let init_response = make_request(
        args,
        reqwest::Method::POST,
        "/v2/verify/init",
        auth_token,
        Some(body),
    );
    let verification_token = init_response
        .get("verificationToken")
        .and_then(|v| v.as_str())
        .expect("Failed to get verification token");

    let auth_token = wait_for_verification(args, verification_token);
    (verification_token.to_string(), auth_token)
}

fn set_password(args: CliArgs) {
    let verification_token = if args.register {
        // For registration, don't verify upfront, pass newAccountEmail instead
        None
    } else {
        Some(verify(&args).0)
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

    // If registering, add newAccountEmail instead of using verification token
    if args.register {
        body.insert(
            "newAccountEmail",
            args.email
                .as_ref()
                .expect("email must be provided")
                .clone()
                .into(),
        );
    }

    let resp = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/accounts/password/init",
        verification_token.as_deref(),
        Some(body),
    );

    // Extract verification token if this was a registration
    let token = if args.register {
        resp.get("verificationToken")
            .and_then(|v| v.as_str())
            .expect("Missing verificationToken for registration")
            .to_string()
    } else {
        verification_token.unwrap()
    };

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
                    client: Some(
                        args.email
                            .as_ref()
                            .expect("email must be provided")
                            .as_bytes(),
                    ),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let record_hex = hex::encode(finish_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("serializedRecord", record_hex.into());

    let mut resp = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/accounts/password/finalize",
        Some(&token),
        Some(body),
    );

    // Handle 2FA if required
    resp = maybe_handle_twofa(&args, resp, &token, "/v2/accounts/password/finalize_2fa");

    // If this was a registration, wait for email verification after password setup
    let auth_token = if args.register {
        wait_for_verification(&args, &token).expect("Failed to get auth token after verification")
    } else {
        resp.get("authToken").unwrap().as_str().unwrap().to_string()
    };

    display_account_details(&args, &auth_token);
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
                    client: Some(
                        args.email
                            .as_ref()
                            .expect("email must be provided")
                            .as_bytes(),
                    ),
                    server: None,
                },
                ..Default::default()
            },
        )
        .map_err(|e| match e {
            ProtocolError::InvalidLoginError => panic!("Invalid credentials"),
            ProtocolError::LibraryError(_) => panic!("Internal opaque_ke error"),
            _ => panic!("Invalid result returned from server"),
        })
        .unwrap();

    let credential_finalization_hex = hex::encode(client_login_finish_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("clientMac", credential_finalization_hex.into());

    let login_token = resp
        .get("loginToken")
        .and_then(|v| v.as_str())
        .expect("Missing loginToken field");

    let mut resp = make_request(
        &args,
        reqwest::Method::POST,
        "/v2/auth/login/finalize",
        Some(login_token),
        Some(body),
    );

    verbose_log(
        &args,
        format!("intermediate login token: {}", login_token).as_str(),
    );

    // Handle 2FA if required
    resp = maybe_handle_twofa(&args, resp, login_token, "/v2/auth/login/finalize_2fa");

    display_account_details(&args, resp.get("authToken").unwrap().as_str().unwrap());
}

fn get_service_token(args: &CliArgs) {
    let mut body = HashMap::new();

    body.insert(
        "service",
        Value::String(
            args.service_name
                .as_ref()
                .expect("service name must be provided")
                .to_string(),
        ),
    );

    let resp = make_request(
        args,
        reqwest::Method::POST,
        "/v2/auth/service_token",
        Some(
            args.token
                .as_ref()
                .expect("auth token is required for acquired session token"),
        ),
        Some(body),
    );

    display_account_details(&args, resp.get("authToken").unwrap().as_str().unwrap());
}

fn enable_totp(args: &CliArgs) {
    println!("Enabling TOTP...");

    // Initialize 2FA
    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("generateQR", true.into());

    let resp = make_request(
        args,
        reqwest::Method::POST,
        "/v2/accounts/2fa/totp/init",
        Some(
            args.token
                .as_ref()
                .expect("auth token is required for enabling TOTP"),
        ),
        Some(body),
    );

    let totp_uri = resp
        .get("uri")
        .and_then(|v| v.as_str())
        .expect("Failed to get TOTP URL");
    let qr_code = resp
        .get("qrCode")
        .and_then(|v| v.as_str())
        .expect("Failed to get QR code")
        .to_string();

    println!("TOTP URL: {}", totp_uri);

    // Open QR code in browser in a separate thread
    thread::spawn(move || {
        if let Err(e) = open::that(qr_code) {
            eprintln!("Failed to open QR code: {}", e);
        }
    });

    // Parse TOTP URL directly with the library
    let totp = TOTP::from_url(totp_uri).expect("Failed to parse TOTP URL");

    // Generate TOTP code
    let code = totp
        .generate_current()
        .expect("Failed to generate TOTP code");
    verbose_log(&args, format!("Generated TOTP code: {}", code).as_str());

    // Finalize 2FA setup
    let mut finalize_body: HashMap<&str, Value> = HashMap::new();
    finalize_body.insert("code", code.into());

    let resp = make_request(
        args,
        reqwest::Method::POST,
        "/v2/accounts/2fa/totp/finalize",
        Some(
            args.token
                .as_ref()
                .expect("auth token is required for enabling TOTP"),
        ),
        Some(finalize_body),
    );

    if let Some(recovery_key) = resp.get("recoveryKey").and_then(|v| v.as_str()) {
        println!("Recovery key: {}", recovery_key);
    }

    println!("TOTP is now enabled");
}

fn main() {
    let args = CliArgs::parse();

    if args.create_service_token {
        get_service_token(&args)
    } else if args.email_verify {
        verify(&args);
    } else if args.email_auth {
        let (_, auth_token) = verify(&args);
        display_account_details(&args, auth_token.unwrap_or_default().as_str());
    } else if args.login {
        login(args);
    } else if args.register || args.reset_password || args.change_password {
        set_password(args);
    } else if args.enable_totp {
        enable_totp(&args);
    } else {
        CliArgs::command()
            .print_help()
            .expect("Failed to display help message");
        eprintln!("Must supply -l, -r, -s, -e, -t, --email-verify, or --enable-totp");
        std::process::exit(1);
    }
}
