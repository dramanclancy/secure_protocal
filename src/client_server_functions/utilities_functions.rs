use openssl::{hash::MessageDigest, rsa::Rsa, sign::Verifier};
use rand::Rng;
use std::{fs::File, io::{Read, Write}, time::{SystemTime, UNIX_EPOCH}};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Serialize, Deserialize};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use openssl::asn1::Asn1Time;
use std::fs;
use super::session_key_functions::ClientKeyFormulation;


#[allow(unused)]
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMessage {
    KeyExchange { user_data: OnlineUserData,},
    TextMessage { user_name: String, text: String },
    ClientList{clients_online: HashMap<String, String>},
    RandomMessage{ClientKeyFormulation:ClientKeyFormulation}
}


#[derive(Serialize, Deserialize, Debug)]
#[allow(unused)]
pub struct OnlineUserData {
    pub user_name: String,
    pub certificate: String,
    pub clients_online: HashMap<String, String>, 
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
pub fn create_new_key_private_key(entity:&str){
    //Key genration
    let rsa=Rsa::generate(2048).unwrap();

    //private key storage
    let file_dir=format!("src/pem/{}_private_key.pem",entity);
    let private_key_pem = rsa.private_key_to_pem().unwrap();
    let mut file = File::create(file_dir).expect("Failed to write to file");
    file.write_all(&private_key_pem).expect("Failed to write private key");
}


#[allow(unused)]
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

#[allow(unused)]
pub fn sign_message(message: &str, entity: &str) -> String {
    // Load private key from PEM file
    let file_path = format!("src/pem/{}_private_key.pem", entity);
    let mut file = File::open(file_path).expect("Failed to open private key file");
    let mut pem = String::new();
    file.read_to_string(&mut pem).expect("Failed to read private key");

    // Parse key and sign
    let rsa = Rsa::private_key_from_pem(pem.as_bytes()).expect("Failed to parse private key");
    let pkey = PKey::from_rsa(rsa).expect("Failed to convert to PKey");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("Failed to create signer");

    signer.update(message.as_bytes()).expect("Failed to update signer");
    let signature = signer.sign_to_vec().expect("Failed to sign");

    // Return base64 encoded signature
    STANDARD.encode(&signature)
}

#[allow(unused)]
pub fn verify_signature(message: &str, base64_signature: &str, entity: &str) -> bool {
    // Load certificate PEM
    let file_path = format!("src/pem/{}_cert.pem", entity);
    let mut file = File::open(file_path).expect("Failed to open certificate file");
    let mut cert_pem = String::new();
    file.read_to_string(&mut cert_pem).expect("Failed to read certificate");

    // Extract public key from certificate
    let cert = X509::from_pem(cert_pem.as_bytes()).expect("Failed to parse certificate");
    let pubkey = cert.public_key().expect("Failed to extract public key");

    // Decode base64 signature
    let signature = STANDARD.decode(base64_signature).expect("Failed to decode base64 signature");

    // Verify the message
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey).expect("Failed to create verifier");
    verifier.update(message.as_bytes()).expect("Failed to update verifier");

    verifier.verify(&signature).unwrap_or(false)
}
use std::collections::HashMap;
#[allow(unused)]
pub fn compare_maps<K: std::cmp::Eq + std::hash::Hash + std::fmt::Debug, V: PartialEq + std::fmt::Debug>(
    old_map: &HashMap<K, V>,
    new_map: &HashMap<K, V>,
) {
    if old_map.len() != new_map.len() {
        println!("Map sizes are different: old = {}, new = {}", old_map.len(), new_map.len());
    }

    for (key, old_value) in old_map {
        match new_map.get(key) {
            Some(new_value) if new_value != old_value => {
                println!("Value changed for key {:?}: {:?} → {:?}", key, old_value, new_value);
            }
            None => {
                println!("Key {:?} was removed", key);
            }
            _ => {} // no change
        }
    }

    for key in new_map.keys() {
        if !old_map.contains_key(key) {
            println!("New key added: {:?}", key);
        }
    }
}

pub fn filter_out_by_key(
    original: &HashMap<String, String>,
    key_to_remove: &str,
) -> HashMap<String, String> {
    original
        .iter()
        .filter(|(k, _)| k != &key_to_remove)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
