//! DNSSEC-Helpers: RSA Signaturen mit PKCS#8 Schlüsselformaten.
//! Hinweis: SHA3-256 ist nicht Standard-Digest bei DNSSEC – Validierung kann abhängig von Validatoren sein.

use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use pem;
use rand::rngs::OsRng;

use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, DecodePublicKey, EncodePublicKey};
// `Signer`/`Verifier` imports removed — we call specific RSA methods directly.

use sha3::{Digest, Sha3_256};
use sha2::Sha256;
use simple_asn1::{to_der, ASN1Block, oid};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ed25519_dalek::{SecretKey, PublicKey, Keypair, Signature, Signer};

/// Berechnet den DNSSEC Key Tag (RFC 4034, Appendix B).
pub fn compute_key_tag(dnskey_rdata: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    for (i, &b) in dnskey_rdata.iter().enumerate() {
        if (i & 1) == 0 {
            acc += (b as u32) << 8;
        } else {
            acc += b as u32;
        }
    }
    acc = (acc + ((acc & 0xffff) << 16)) >> 16;
    (acc & 0xffff) as u16
}

/// Baut das DNSKEY-RDATA aus Komponenten.
pub fn dnskey_rdata_from_parts(
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key_b64: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let pk = general_purpose::STANDARD.decode(public_key_b64.trim())?;
    let mut r = Vec::with_capacity(4 + pk.len());
    r.extend_from_slice(&flags.to_be_bytes());
    r.push(protocol);
    r.push(algorithm);
    r.extend_from_slice(&pk);
    Ok(r)
}

/// Berechnet DS mit SHA3-256 (nicht standardmäßig in DNSSEC).
pub fn compute_ds_sha3_256(dnskey_rdata: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(dnskey_rdata);
    hasher.finalize().to_vec()
}

/// Compute DS using SHA-256 (digest type 2 per RFC 4034)
pub fn compute_ds_sha256(dnskey_rdata: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(dnskey_rdata);
    hasher.finalize().to_vec()
}

/// Formatiert DS in Präsentationsform „keyTag algorithm digestType digestHex“.
pub fn format_ds_presentation(
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: &[u8],
) -> String {
    format!("{} {} {} {}", key_tag, algorithm, digest_type, hex::encode(digest))
}

/// Baut ein ASN.1 DigestInfo für SHA3-256 manuell.
///
/// OID für SHA3-256: 2.16.840.1.101.3.4.2.8
fn make_digestinfo_sha3_256(hash: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let oid_sha3_256 = oid!(2, 16, 840, 1, 101, 3, 4, 2, 8);
    let seq = ASN1Block::Sequence(0, vec![
        ASN1Block::Sequence(0, vec![
            ASN1Block::ObjectIdentifier(0, oid_sha3_256),
            ASN1Block::Null(0),
        ]),
        ASN1Block::OctetString(0, hash.to_vec()),
    ]);
    Ok(to_der(&seq)?)
}

/// Signiert eine Nachricht mit einem RSA-Privatkey (PEM PKCS#8) unter Verwendung
/// von PKCS#1 v1.5: SHA3-256 wird gehasht, in DigestInfo eingebettet, und dann signiert.
pub fn sign_pkcs1v15_sha3_256(private_pem: &str, msg: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Parse PEM
    let pem = pem::parse(private_pem)?;
    if pem.tag != "PRIVATE KEY" {
        return Err("Erwartet PKCS#8 PEM: BEGIN PRIVATE KEY".into());
    }

    // PrivateKey laden mit PKCS#8
    let key = RsaPrivateKey::from_pkcs8_der(&pem.contents)
        .map_err(|e| format!("Fehler beim Parsen des RSA Private-Key: {}", e))?;

    // SHA3-256 Hash
    let hash = Sha3_256::digest(msg);

    // DigestInfo bauen
    let di = make_digestinfo_sha3_256(&hash)?;

    // PKCS#1 v1.5 Signatur-Schema
    let padding = Pkcs1v15Sign::new_unprefixed(); // kein Präfix, wir bauen selbst DigestInfo
    let mut rng = OsRng;
    let sig = key.sign_with_rng(&mut rng, padding, &di)?;
    Ok(sig)
}

/// Sign message using algorithm identifier. Supports RSA (alg 8) and Ed25519 (alg 15).
pub fn sign_by_algorithm(private_pem: &str, algorithm: u8, msg: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    match algorithm {
        8 => sign_pkcs1v15_sha3_256(private_pem, msg),
        15 => {
            // Ed25519: expect PKCS#8 PRIVATE KEY DER inside PEM
            let pem = pem::parse(private_pem)?;
            if pem.tag != "PRIVATE KEY" {
                return Err("Expected PKCS#8 PRIVATE KEY PEM for Ed25519".into());
            }
            let kp = Ed25519KeyPair::from_pkcs8(&pem.contents)
                .map_err(|e| format!("Ed25519 key parse error: {:?}", e))?;
            let sig = kp.sign(msg);
            Ok(sig.as_ref().to_vec())
        }
        _ => Err(format!("Unsupported signing algorithm: {}", algorithm).into()),
    }
}

/// Sign using raw private key bytes (PEM or raw seed). This handles RSA PEM and Ed25519
/// either as PKCS#8 PEM or raw 32-byte seed.
pub fn sign_by_algorithm_bytes(private_key_bytes: &[u8], algorithm: u8, msg: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    match algorithm {
        8 => {
            let priv_str = std::str::from_utf8(private_key_bytes)?;
            sign_pkcs1v15_sha3_256(priv_str, msg)
        }
        15 => {
            // Try PKCS#8 PEM first
            if let Ok(s) = std::str::from_utf8(private_key_bytes) {
                if let Ok(pem) = pem::parse(s) {
                    if pem.tag == "PRIVATE KEY" {
                        if let Ok(kp) = Ed25519KeyPair::from_pkcs8(&pem.contents) {
                            let sig = kp.sign(msg);
                            return Ok(sig.as_ref().to_vec());
                        }
                    }
                }
            }

            // Fallback: treat private_key_bytes as raw seed (32 bytes)
            if private_key_bytes.len() == 32 {
                let secret = SecretKey::from_bytes(private_key_bytes).map_err(|e| format!("secret parse: {:?}", e))?;
                let public = PublicKey::from(&secret);
                let kp = Keypair{ secret, public };
                let sig: Signature = kp.sign(msg);
                return Ok(sig.to_bytes().to_vec());
            }

            Err("Unsupported Ed25519 private key format; expected PKCS#8 PEM or 32-byte seed".into())
        }
        _ => Err(format!("Unsupported signing algorithm: {}", algorithm).into()),
    }
}

/// Verifiziert eine Signatur mit dem Public-Key (PEM PKCS#8) und dem Original-Message.
pub fn verify_pkcs1v15_sha3_256(public_pem: &str, msg: &[u8], sig: &[u8]) -> Result<bool, Box<dyn Error>> {
    // PEM parsen
    let pem = pem::parse(public_pem)?;
    
    // Nur PKCS#8 Public Key (moderner Standard)
    if pem.tag != "PUBLIC KEY" {
        return Err("Erwartet PKCS#8 PUBLIC KEY PEM".into());
    }
    
    let pubkey = RsaPublicKey::from_public_key_der(&pem.contents)?;

    // Hash und DigestInfo wie beim Signieren
    let hash = Sha3_256::digest(msg);
    let di = make_digestinfo_sha3_256(&hash)?;

    let padding = Pkcs1v15Sign::new_unprefixed();
    match pubkey.verify(padding, &di, sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generiert einen neuen RSA-Privat-Schlüssel (PEM PKCS#8) mit gegebener Bitlänge.
pub fn generate_rsa_private_pem(bits: usize) -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = rand::rngs::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, bits)?;
    
    // PKCS#8 statt PKCS#1 - das moderne Format
    let der = key.to_pkcs8_der()?;  // Benutzt EncodePrivateKey Trait
    let pem = pem::Pem {
        tag: "PRIVATE KEY".to_string(),  // PKCS#8 Header
        contents: der.as_bytes().to_vec(),
    };
    Ok(pem::encode(&pem))
}

/// Konvertiert einen PKCS#1 Private Key zu PKCS#8 Format
pub fn convert_pkcs1_to_pkcs8(pkcs1_pem: &str) -> Result<String, Box<dyn Error>> {
    let pem = pem::parse(pkcs1_pem)?;
    if pem.tag != "RSA PRIVATE KEY" {
        return Err("Erwartet PKCS#1 RSA PRIVATE KEY PEM".into());
    }
    
    // KORREKT: Verwende from_pkcs8_der für PKCS#8 Schlüssel
    // Aber für PKCS#1 zu PKCS#8 Konvertierung müssen wir zuerst den PKCS#1 Key lesen
    use rsa::pkcs1::DecodeRsaPrivateKey; // Für PKCS#1 Import
    use rsa::pkcs8::EncodePrivateKey;    // Für PKCS#8 Export
    
    let key = RsaPrivateKey::from_pkcs1_der(&pem.contents)?; // PKCS#1 lesen
    let der = key.to_pkcs8_der()?; // Als PKCS#8 exportieren
    let pkcs8_pem = pem::Pem {
        tag: "PRIVATE KEY".to_string(), // PKCS#8 Header
        contents: der.as_bytes().to_vec(),
    };
    Ok(pem::encode(&pkcs8_pem))
}

/// Extrahiert Public Key aus Private Key im PKCS#8 Format
pub fn extract_public_key(private_pem: &str) -> Result<String, Box<dyn Error>> {
    let pem = pem::parse(private_pem)?;
    // Try RSA PKCS#8 first
    if let Ok(priv_rsa) = RsaPrivateKey::from_pkcs8_der(&pem.contents) {
        let pub_key = RsaPublicKey::from(&priv_rsa);
        let pub_der = pub_key.to_public_key_der()?;
        let pub_pem = pem::Pem { tag: "PUBLIC KEY".to_string(), contents: pub_der.as_bytes().to_vec() };
        return Ok(pem::encode(&pub_pem));
    }

    // Try Ed25519 PKCS#8
    if let Ok(kp) = Ed25519KeyPair::from_pkcs8(&pem.contents) {
        // Build SubjectPublicKeyInfo per RFC8410: algorithm OID 1.3.101.112, no params
        let oid_ed25519 = oid!(1,3,101,112);
        let alg = ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, oid_ed25519)]);
        let pub_bytes = kp.public_key().as_ref().to_vec();
        let spk = ASN1Block::BitString(0, 0, pub_bytes);
        let seq = ASN1Block::Sequence(0, vec![alg, spk]);
        let der = to_der(&seq)?;
        let pub_pem = pem::Pem { tag: "PUBLIC KEY".to_string(), contents: der };
        return Ok(pem::encode(&pub_pem));
    }

    Err("Unsupported private key format for public extraction".into())
}

/// Liefert die aktuelle Zeit als UNIX-Sekunden (z. B. für RRSIG Inception/Expiration).
pub fn now_unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let pem = generate_rsa_private_pem(2048).unwrap();
        let msg = b"hello dnssec";
        let sig = sign_pkcs1v15_sha3_256(&pem, msg).unwrap();

        // Public key extrahieren mit neuer Funktion
        let pub_pem_str = extract_public_key(&pem).unwrap();

        let ok = verify_pkcs1v15_sha3_256(&pub_pem_str, msg, &sig).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_pkcs1_to_pkcs8_conversion() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        // generate a PKCS#1 PEM directly
        let mut rng = rand::rngs::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let der = key.to_pkcs1_der().unwrap();
        let pkcs1_pem = pem::Pem { tag: "RSA PRIVATE KEY".to_string(), contents: der.as_bytes().to_vec() };
        let pkcs1_pem = pem::encode(&pkcs1_pem);
        let pkcs8_pem = convert_pkcs1_to_pkcs8(&pkcs1_pem).unwrap();
        
        // Teste dass der konvertierte Key funktioniert
        let msg = b"conversion test";
        let sig = sign_pkcs1v15_sha3_256(&pkcs8_pem, msg).unwrap();
        let pub_key = extract_public_key(&pkcs8_pem).unwrap();
        let ok = verify_pkcs1v15_sha3_256(&pub_key, msg, &sig).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_compute_ds_sha256() {
        let data = b"abc";
        let d = compute_ds_sha256(data);
        // SHA256("abc") known value
        let expected_hex = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD".to_lowercase();
        assert_eq!(hex::encode(d).to_lowercase(), expected_hex);
    }
}