//! Cryptographic operations: SHA-256, Merkle Tree computation, and Ed25519 signatures.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Compute SHA-256 hex string of raw bytes
pub fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hex string of a file
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    use std::io::Read;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Compute Merkle Root hash from a list of transaction/item hashes
pub fn compute_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return sha256_digest(b"EMPTY_MERKLE_TREE");
    }
    let mut current_layer: Vec<String> = hashes.to_vec();

    while current_layer.len() > 1 {
        let mut next_layer = Vec::new();
        for chunk in current_layer.chunks(2) {
            if chunk.len() == 2 {
                let combined = format!("{}{}", chunk[0], chunk[1]);
                next_layer.push(sha256_digest(combined.as_bytes()));
            } else {
                // Odd number of elements: duplicate last item
                let combined = format!("{}{}", chunk[0], chunk[0]);
                next_layer.push(sha256_digest(combined.as_bytes()));
            }
        }
        current_layer = next_layer;
    }

    current_layer[0].clone()
}

/// Key custody manager for Ed25519 authority keys
pub struct KeyAuthority {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl KeyAuthority {
    /// Load existing authority key from disk or generate a new persistent one
    pub fn load_or_generate(privkey_path: &Path, pubkey_path: &Path) -> Result<Self, String> {
        if privkey_path.exists() {
            let key_bytes = fs::read(privkey_path).map_err(|e| e.to_string())?;
            if key_bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&key_bytes);
                let signing_key = SigningKey::from_bytes(&seed);
                let verifying_key = signing_key.verifying_key();
                return Ok(Self {
                    signing_key,
                    verifying_key,
                });
            }
        }

        // Generate new key
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Persist keys
        if let Some(parent) = privkey_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(privkey_path, signing_key.to_bytes());
        let _ = fs::write(pubkey_path, hex::encode(verifying_key.to_bytes()));

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Sign data bytes and return hex-encoded signature
    pub fn sign_hex(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }

    /// Public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Verify signature with public key hex string
    pub fn verify_signature_hex(
        pubkey_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<bool, String> {
        let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| e.to_string())?;
        if pubkey_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        let mut pubkey_arr = [0u8; 32];
        pubkey_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| e.to_string())?;

        let sig_bytes = hex::decode(signature_hex).map_err(|e| e.to_string())?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        Ok(verifying_key.verify(message, &signature).is_ok())
    }
}
