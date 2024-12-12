module github.com/brave/accounts/misc/test-client-go

go 1.23.1

require github.com/bytemare/opaque v0.0.0

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/nistec v0.0.3 // indirect
	github.com/bytemare/crypto v0.6.0 // indirect
	github.com/bytemare/hash v0.3.0 // indirect
	github.com/bytemare/hash2curve v0.3.0 // indirect
	github.com/bytemare/ksf v0.1.0 // indirect
	github.com/bytemare/secp256k1 v0.1.2 // indirect
	github.com/gtank/ristretto255 v0.1.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace github.com/bytemare/opaque v0.0.0 => github.com/brave-experiments/opaque v0.0.0-20241101041742-9ecb8a57b3d4
