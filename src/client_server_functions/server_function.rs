// Imports standard filesystem and IO modules, including file handling and buffered reading
use std::fs::{self, File, OpenOptions}; 
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

// Imports required OpenSSL modules for cryptographic operations
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;

// Imports internal modules for decryption and utility functions
use super::decryption_module::{private_key_decrypt, public_key_decrypt};
use super::utilities_functions::{self, hash_and_encode, verify_signature};

/// Splits a string on the custom delimiter `||`.
/// Returns a tuple of two or three parts based on split length.
#[allow(unused)]
pub fn split(text: String) -> Option<(String, String, Option<String>)> {
    let parts: Vec<&str> = text.split("||").collect();
    match parts.len() {
        2 => Some((parts[0].to_string(), parts[1].to_string(), None)),
        3 => Some((parts[0].to_string(), parts[1].to_string(), Some(parts[2].to_string()))),
        _ => None, // Returns None if not exactly 2 or 3 parts
    }
}

/// Verifies that a given timestamp (as string) is within 1 day of the current system time.
#[allow(unused)]
fn verify_time(time_as_secs: String) -> Result<(), String> {
    let t: u64 = match time_as_secs.parse() {
        Ok(val) => val,
        Err(_) => return Err("Failed to parse time".to_string()),
    };
    let sys_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let diff = sys_time.as_secs() - t;

    if diff < 86400 {
        Ok(())
    } else {
        Err("Time difference is greater than 1 day".to_string())
    }
}

/// Verifies nonce freshness by checking if it's already present in a text file.
/// If not, appends the nonce to the file to prevent reuse.
fn verify_nonce(nonce: String) -> Result<(), String> {
    let file_dir = format!("src/nonce.txt");
    let mut nonce_file = File::open(file_dir).expect("Failed to open nonce file");
    let reader = BufReader::new(nonce_file);

    for line in reader.lines() {
        match line {
            Ok(line) => {
                if line.trim() == nonce {
                    return Err("Nonce already used".to_string());
                }
            },
            Err(error) => eprintln!("Error reading line: {}", error),
        }
    }

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("src/nonce.txt")
        .map_err(|e| format!("Failed to open file for appending: {}", e))?;

    writeln!(file, "{}", nonce).map_err(|e| format!("Failed to write nonce: {}", e))?;
    Ok(())
}

/// Verifies the hash by comparing the received hash with one computed from the data.
/// Also verifies the digital signature using the provided username.
pub fn verify_hash(hash: String, hash_signature: String, username: String, data: String) -> Result<(), String> {
    let signature_valid = verify_signature(&hash, &hash_signature, &username);
    let computed_hash = hash_and_encode(data);

    if hash == computed_hash && signature_valid {
        Ok(())
    } else {
        Err("Hash mismatch: signature invalid".to_string())
    }
}

/// Retrieves a PEM-formatted certificate for a given entity and verifies its format.
pub fn get_cert(entity: &str) -> String {
    let file_path = format!("src/pem/{}_cert.pem", entity);
    let mut file = File::open(&file_path)
        .expect("Failed to open certificate file");

    let mut cert_pem = String::new();
    file.read_to_string(&mut cert_pem)
        .expect("Failed to read certificate");

    let _ = X509::from_pem(cert_pem.as_bytes())
        .expect("Failed to parse certificate");

    cert_pem
}

/// Struct representing the server entity.
#[derive(Clone)]
#[allow(unused)]
pub struct Server {
    server_name: String,
}

/// Struct representing a client entity with public attributes.
pub struct Client {
    pub user_name: String,
    pub cert: String,
    pub port: String,
}

#[allow(unused)]
impl Server {
    /// Creates and returns a new Server instance.
    pub fn new(server_name: String) -> Self {
        Self { server_name }
    }

    /// Authenticates user data by validating decrypted nonce, time, and hash.
    /// Returns all fields if validation passes; otherwise, returns error.
    pub fn authenticate_user_data(&self, cipher_text: String, hash_signature: String, hash: String)
        -> Result<(String, String, String), String> 
    {
        let decrypted_data = private_key_decrypt(cipher_text, self.server_name.clone());
        let (_nonce, _time, _username) = split(decrypted_data.clone()).unwrap();
        let time_valid_status = verify_time(_time.clone()).is_ok();
        let nonce_valid_status = verify_nonce(_nonce.clone()).is_ok();
        let username = _username.unwrap();
        let hash_valid_status = verify_hash(hash, hash_signature, username.clone(), decrypted_data).is_ok();

        if time_valid_status && nonce_valid_status && hash_valid_status {
            Ok((_nonce, _time, username))
        } else {
            Err("Couldnt authenticate".to_string())
        }
    }

    /// Returns the name of the server.
    pub fn get_name(&self) -> String {
        self.server_name.clone()
    }
}
