use rsa::{RsaPrivateKey, RsaPublicKey};

use std::fs;
use std::path::Path;


// für Schlüssel-IO
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
//use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
// für Signatur traits
use rsa::signature::RandomizedSigner;

// PSS signing key
use rsa::pss::BlindedSigningKey;

// RNG
use rand::rngs::OsRng;

// Hash
//use rsa::sha2::{Digest, Sha256}; // falls noch nicht importiert


pub fn generate_key_pair(domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    let keys_dir = "keys";
    if !Path::new(keys_dir).exists() {
        fs::create_dir(keys_dir)?;
    }

    let private_key_der = private_key.to_pkcs8_der()?;
    let private_key_path = format!("{}/{}.key", keys_dir, domain);
    fs::write(&private_key_path, private_key_der.as_bytes())?;

    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF)?;
    let public_key_path = format!("{}/{}.pub", keys_dir, domain);
    fs::write(&public_key_path, public_key_pem)?;

    println!("DNSSEC-Schlüssel für {} generiert und in {} gespeichert.", domain, keys_dir);
    Ok(())
}

pub fn load_private_key(domain: &str) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    let key_path = format!("keys/{}.key", domain);
    let key_data = fs::read(key_path)?;
    let private_key = RsaPrivateKey::from_pkcs8_der(&key_data)?;
    Ok(private_key)
}