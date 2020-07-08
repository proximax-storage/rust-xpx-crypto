<p align="center"><a href="https://www.rust-lang.org" target="_blank" rel="noopener noreferrer"><img width="301" src="https://user-images.githubusercontent.com/29048783/72931755-72142680-3d2c-11ea-9e7a-252e995f1d0f.png" alt="Rust logo"></a></p>
<h1 align="center">ProximaX Sirius Blockchain Crypto Rust</h1>

Official ProximaX Sirius Blockchain implementation ed26619 encryption modules for Rust.

The ProximaX Sirius Blockchain Crypto Rust works as a lightweight Rust library for interacting with the Sirius Blockchain.

### Usage
First, add this to your `Cargo.toml`:

```toml
[dependencies]
xpx-chain-crypto = { git = "https://github.com/proximax-storage/rust-xpx-crypto" }
```

### Example
```rust
use xpx_chain_crypto::{Keypair, PublicKey, SecretKey, Signature};

fn main() {
    let sk_hex =
        hex::decode("68f50e10e5b8be2b7e9ddb687a667d6e94dd55fe02b4aed8195f51f9a242558b").unwrap();

    let message: &[u8] = b"ProximaX Limited";

    let secret_key: SecretKey = SecretKey::from_bytes(&sk_hex).unwrap();
    println!("PrivateKey: {:?}", hex::encode(secret_key.to_bytes()));

    let public_key: PublicKey = PublicKey::from(&secret_key);
    println!("PublicKey: \t{:?}", hex::encode(public_key.to_bytes()));

    let key_pair = Keypair {
        secret: secret_key,
        public: public_key,
    };

    println!("PublicKey: \t{:?}", key_pair.public);

    let sig: Signature = key_pair.sign(&message);
    println!("Sig: \t\t{:?}", hex::encode(sig.to_bytes().to_vec()));
    println!("Verify: \t{}", key_pair.verify(&message, &sig).is_ok());
}
```

