module github.com/brave/accounts/misc/test-client-go

go 1.24.0

toolchain go1.24.4

require github.com/bytemare/opaque v0.0.0

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/nistec v0.0.3 // indirect
	github.com/bytemare/ecc v0.8.3 // indirect
	github.com/bytemare/hash v0.5.0 // indirect
	github.com/bytemare/hash2curve v0.5.1 // indirect
	github.com/bytemare/ksf v0.2.0 // indirect
	github.com/bytemare/secp256k1 v0.2.0 // indirect
	github.com/gtank/ristretto255 v0.1.2 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/bytemare/opaque v0.0.0 => github.com/brave-experiments/opaque v0.0.0-20250429210303-c2ce323b78e0
