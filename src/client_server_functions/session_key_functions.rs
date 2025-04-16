pub fn generate_random_256() -> [u8; 32] {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random()
}

pub fn encrypt_with_cert(cert_pem: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    use openssl::x509::X509;
    use openssl::rsa::Padding;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use base64::{engine::general_purpose::STANDARD, Engine};

    let cert = X509::from_pem(cert_pem.as_bytes())?;
    let pub_key: PKey<openssl::pkey::Public> = cert.public_key()?;
    let rsa = pub_key.rsa()?;

    let mut encrypted = vec![0; rsa.size() as usize];
    rsa.public_encrypt(data, &mut encrypted, Padding::PKCS1)?;
    Ok(STANDARD.encode(encrypted))
    
}



pub fn derive_session_key(my_random: &[u8], peer_random: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(my_random);
    hasher.update(peer_random);
    let result = hasher.finalize();

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(&result[..32]);
    session_key
}

pub fn aes_encrypt_message(session_key: &[u8; 32], iv: &[u8; 16], message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use openssl::symm::{encrypt, Cipher};

    Ok(encrypt(
        Cipher::aes_256_cbc(),
        session_key,
        Some(iv),
        message,
    )?)
}

