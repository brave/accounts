# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Commands

### Build and Development
- `cargo build` - Build the project
- `cargo run -- [args]` - Run the test client with arguments
- `cargo test` - Run tests
- `cargo clippy` - Run linter to catch common mistakes
- `cargo check` - Check code without building

### Running the Test Client
The main binary is a CLI tool for testing Brave Accounts API endpoints. Common usage patterns:
- `cargo run -- --help` - Show all available options
- `cargo run -- --login --email user@example.com --password pass123` - Login flow
- `cargo run -- --register --email user@example.com --password pass123` - Registration flow
- `cargo run -- --logout --token <auth_token>` - Logout with auth token
- `cargo run -- --enable-totp --token <auth_token>` - Enable TOTP 2FA

## Architecture

### Core Structure
- `src/main.rs` - Main CLI entry point with argument parsing and flow control
- `src/util.rs` - Shared utilities for HTTP requests and response handling

### Key Components
1. **OPAQUE Protocol Integration**: Uses `opaque-ke` crate for password-authenticated key exchange
2. **CLI Interface**: Built with `clap` for command-line argument parsing
3. **HTTP Client**: Uses `reqwest` blocking client for API communication
4. **2FA Support**: Integrates TOTP authentication and recovery keys
5. **Session Management**: Handles auth tokens, sessions, and logout functionality

### Authentication Flow
The client implements the OPAQUE protocol for secure password authentication:
1. Registration: `ClientRegistration::start()` → server interaction → `finish()`
2. Login: `ClientLogin::start()` → server interaction → `finish()`
3. Both flows support optional 2FA verification

### API Endpoints
Base URL defaults to `http://localhost:8080` with these main endpoints:
- `/v2/accounts/password/*` - Password operations
- `/v2/auth/*` - Authentication and validation
- `/v2/verify/*` - Email verification flows
- `/v2/sessions/*` - Session management

### Dependencies
- `opaque-ke` - OPAQUE protocol implementation (local path dependency)
- `argon2` - Key stretching function for OPAQUE
- `reqwest` - HTTP client library
- `totp-rs` - TOTP code generation for 2FA
- `clap` - CLI argument parsing