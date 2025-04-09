use openssl::{rsa::Rsa, sign};
use rand::Rng;
use std::{fs::File, io::{Read, Write}, time::{SystemTime, UNIX_EPOCH}};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Serialize, Deserialize};

use openssl::pkey::PKey;
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use openssl::asn1::Asn1Time;
use std::fs;


#[allow(unused)]
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMessage {
    KeyExchange { user_data: OnlineUserData},
    TextMessage { user_name: String, text: String },
}
#[derive(Serialize, Deserialize, Debug)]
#[allow(unused)]
pub struct OnlineUserData{
    pub user_name:String,
    pub certificate:String, 
}


#[allow(unused)]
pub fn time_now()->u64{
    
    return SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();   
}

#[allow(unused)]
pub fn nonce()->u32{
    let mut rng = rand::rng(); // Create a random number generator
    return rng.random_range(1..=1_000_000_000); //
}

#[allow(unused)]
pub fn hash_and_encode(data: String) -> String {
    let mut hasher = Sha256::new();

   
    hasher.update(data.as_str().as_bytes());

    // Read hash digest and consume hasher
    let hashed_data = hasher.finalize();

    // Encode the hashed data to Base64 and convert to String
    let encoded_data = STANDARD.encode(&hashed_data);
    encoded_data
}

#[allow(unused)]
fn create_new_key(){
    //Key genration
    let rsa=Rsa::generate(2048).unwrap();

    //private key storage
    let private_key_pem = rsa.private_key_to_pem().unwrap();
    let mut file = File::create("src/server_private_key.pem").expect("Failed to write to file");
    file.write_all(&private_key_pem).expect("Failed to write private key");
    

    //public key generation
    let n = rsa.n().to_owned().unwrap(); // Modulus
    let e = rsa.e().to_owned().unwrap(); // Exponent
    let rsa_public = Rsa::from_public_components(n, e).unwrap();

    //public key storage
    let public_key_pem=rsa_public.public_key_to_pem().unwrap();
    let mut file = File::create("src/server_public_key.pem").expect("Failed to write to file");
    file.write_all(&public_key_pem).expect("Failed to write public key");

}



pub fn generate_cert_from_pem(user_name: &str) -> X509 {
    // Load private key PEM
    let private_key_pem = fs::read(format!("src/pem/{}_private_key.pem", user_name))
        .expect("Failed to read private key");
    let private_key = PKey::private_key_from_pem(&private_key_pem)
        .expect("Failed to parse private key");

    // Create subject/issuer name
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", user_name)
        .unwrap(); // Common Name
    let name = name_builder.build();

    // Create certificate
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap(); // self-signed
    builder.set_pubkey(&private_key).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap(); // 1 year
    builder.sign(&private_key, openssl::hash::MessageDigest::sha256()).unwrap();

    let cert = builder.build();

    // Optional: write to disk
    let cert_pem = cert.to_pem().unwrap();
    let mut file = fs::File::create(format!("src/pem/{}_cert.pem", user_name)).unwrap();
    file.write_all(&cert_pem).unwrap();

    cert
}