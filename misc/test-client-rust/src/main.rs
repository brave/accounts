use std::{
    collections::HashMap,
    io::{stdin, stdout, Write},
};

use argon2::Argon2;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand::rngs::OsRng;
use serde_json::Value;

#[allow(dead_code)]
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = Argon2<'static>;
}

fn post_request(
    url: &str,
    bearer_token: Option<&str>,
    body: HashMap<&str, Value>,
) -> HashMap<String, String> {
    let client = reqwest::blocking::Client::new();
    let mut request_builder = client.post(url).json(&body);

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
        .json::<HashMap<String, String>>()
        .expect("Failed to parse response as HashMap<String, String>")
}

pub fn prompt_credentials() -> (String, String) {
    print!("Enter email: ");
    stdout().flush().unwrap();
    let mut email = String::new();
    stdin().read_line(&mut email).unwrap();

    print!("Enter password: ");
    stdout().flush().unwrap();
    let mut password = String::new();
    stdin().read_line(&mut password).unwrap();

    email = email.trim().to_string();
    password = password.trim().to_string();

    (email, password)
}

fn set_password(change_password: bool) {
    print!("Enter verification/auth token: ");
    stdout().flush().unwrap();
    let mut token = String::new();
    stdin().read_line(&mut token).unwrap();

    token = token.trim().to_string();
    let (email, password) = prompt_credentials();

    let mut client_rng = OsRng;

    let registration_request =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();
    let registration_request_hex = hex::encode(registration_request.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("blindedMessage", registration_request_hex.into());
    body.insert("serializeResponse", true.into());

    let init_url = if change_password {
        "http://localhost:8080/v2/accounts/change_pwd/init"
    } else {
        "http://localhost:8080/v2/accounts/setup/init"
    };
    let resp = post_request(init_url, Some(&token), body);

    let resp_bin = hex::decode(resp.get("serializedResponse").unwrap()).unwrap();

    let finish_result = registration_request
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&resp_bin).unwrap(),
            ClientRegistrationFinishParameters {
                identifiers: Identifiers {
                    client: Some(email.as_bytes()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let record_hex = hex::encode(finish_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("serializedRecord", record_hex.into());

    let finalize_url = if change_password {
        "http://localhost:8080/v2/accounts/change_pwd/finalize"
    } else {
        "http://localhost:8080/v2/accounts/setup/finalize"
    };
    let resp = post_request(finalize_url, Some(&token), body);

    println!("auth token: {}", resp.get("authToken").unwrap())
}

fn login() {
    let (email, password) = prompt_credentials();

    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

    let credential_request_hex = hex::encode(client_login_start_result.message.serialize());

    let mut body: HashMap<&str, Value> = HashMap::new();
    body.insert("serializedKE1", credential_request_hex.into());
    body.insert("email", email.clone().into());

    let resp = post_request("http://localhost:8080/v2/auth/login/init", None, body);

    let ke2_bin = hex::decode(resp.get("serializedKE2").unwrap()).unwrap();

    let client_login_finish_result = client_login_start_result
        .state
        .finish(
            password.as_bytes(),
            CredentialResponse::deserialize(&ke2_bin).unwrap(),
            ClientLoginFinishParameters {
                identifiers: Identifiers {
                    client: Some(email.as_bytes()),
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
        "http://localhost:8080/v2/auth/login/finalize",
        Some(resp.get("akeToken").unwrap()),
        body,
    );

    println!("auth token: {}", resp.get("authToken").unwrap())
}

fn main() {
    print!("1. Login\n2. Register\n3. Change password\nEnter choice (1, 2 or 3): ");
    stdout().flush().unwrap();

    let mut choice = String::new();
    stdin().read_line(&mut choice).unwrap();

    match choice.trim() {
        "1" => login(),
        "2" => set_password(false),
        "3" => set_password(true),
        _ => println!("Invalid choice"),
    }
}
