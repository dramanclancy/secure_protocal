use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;


use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;


use super::decryption_module::{private_key_decrypt, public_key_decrypt};
use super::utilities_functions::{self, hash_and_encode, verify_signature};

#[allow(unused)]
pub fn split(text: String) -> Option<(String, String, Option<String>)> {
    let parts: Vec<&str> = text.split("||").collect();
    
    match parts.len() {
        2 => Some((parts[0].to_string(), parts[1].to_string(), None)),
        3 => Some((parts[0].to_string(), parts[1].to_string(), Some(parts[2].to_string()))),
        _ => None, // Return None if the text doesn't split into exactly two or three parts
    }
}
#[allow(unused)]
fn verify_time(time_as_secs: String) -> Result<(), String> {
    
    let t: u64 = match time_as_secs.parse() {
        Ok(val) => val,
        Err(_) => return Err("Failed to parse time".to_string()),
    };

    let sys_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let diff=(sys_time.as_secs() - t);

    if (diff) < 86400 {
        Ok(())
    } else {
        Err("Time difference is greater than 1 day".to_string())
    }
}

fn verify_nonce(nonce:String)->Result<(),String>{
    let file_dir=format!("src/nonce.txt");
    let mut nonce_file = File::open(file_dir).expect("Failed to open nonce file");
    let reader = BufReader::new(nonce_file);
    // Read the file line by line
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
        return Ok(())
}

pub fn verify_hash(hash: String, hash_signature: String, username: String,data:String) -> Result<(), String> {
    // 1. Decrypt the signed hash using the sender's public key
    let signature_valid = verify_signature(&hash, &hash_signature,&username);

    // 2. Hash the decrypted data (this is what the original sender supposedly hashed)
    let computed_hash = hash_and_encode(data);
   

    // 3. Compare
    if hash == computed_hash && signature_valid {
        Ok(())
    } else {
        Err("Hash mismatch: signature invalid".to_string())
    }
}



pub fn get_cert(entity: &str) -> String {
    // Build the file path using the provided entity name.
    let file_path = format!("src/pem/{}_cert.pem", entity);
    
    // Open the certificate file.
    let mut file = File::open(&file_path)
        .expect("Failed to open certificate file");
    
    // Read the file contents into a String.
    let mut cert_pem = String::new();
    file.read_to_string(&mut cert_pem)
        .expect("Failed to read certificate");
    
    // Optionally, parse the certificate to ensure it is valid.
    // The result is discarded since we want the certificate as-is.
    let _ = X509::from_pem(cert_pem.as_bytes())
        .expect("Failed to parse certificate");
    
    // Return the certificate in PEM format.
    cert_pem
}

#[derive(Clone)]
#[allow(unused)]
pub struct Server{
    server_name:String,
}


pub struct Client{
    pub user_name:String,
    pub cert:String,
    pub port:String
}
#[allow(unused)]
impl Server{
    pub fn new(server_name:String)->Self{Self{server_name}}
    
    pub fn authenticate_user_data(&self,cipher_text:String,hash_signature:String,hash:String)->Result<(String,String,String),String>{
    let decrypted_data=private_key_decrypt(cipher_text, self.server_name.clone());
    let (_nonce,_time,_username)=split(decrypted_data.clone()).unwrap();
    let time_valid_status= verify_time(_time.clone()).is_ok();
    let nonce_valid_status=verify_nonce(_nonce.clone()).is_ok();
    let username=_username.unwrap();
    let hash_valid_status=verify_hash(hash,hash_signature,username.clone(),decrypted_data).is_ok();
    
    

    if(time_valid_status&&nonce_valid_status&&hash_valid_status){
        return Ok(
            (_nonce,
             _time,
             username
            )
        );
    }else{
        Err("Couldnt authenticate".to_string())
    }
        
        
    }
    
    pub fn get_name(&self) -> String {
        self.server_name.clone()
    }
    
}
