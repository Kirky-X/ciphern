use crate::error::{CryptoError, Result};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

pub fn generate_openssl_rsa_private_key(bits: u32) -> Result<Vec<u8>> {
    if bits < 2048 {
        return Err(CryptoError::KeyError(format!(
            "RSA key size {} is too small, minimum is 2048 bits",
            bits
        )));
    }

    let rsa = Rsa::generate(bits).map_err(|e| {
        CryptoError::KeyError(format!("Failed to generate RSA key with OpenSSL: {}", e))
    })?;

    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| CryptoError::KeyError(format!("Failed to create PKey from RSA: {}", e)))?;

    let der_bytes = pkey.private_key_to_der().map_err(|e| {
        CryptoError::KeyError(format!("Failed to convert private key to DER: {}", e))
    })?;

    Ok(der_bytes)
}

pub fn convert_rsa_der_to_pkcs8(der_bytes: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::private_key_from_der(der_bytes).map_err(|e| {
        CryptoError::KeyError(format!("Failed to parse RSA private key DER: {}", e))
    })?;

    let pkcs8_bytes = pkey
        .private_key_to_pkcs8()
        .map_err(|e| CryptoError::KeyError(format!("Failed to convert to PKCS#8: {}", e)))?;

    Ok(pkcs8_bytes)
}
