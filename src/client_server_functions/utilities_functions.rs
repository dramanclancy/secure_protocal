use openssl::rsa::Rsa;
use rand::Rng;
use std::{fs::File, io::Write, time::{SystemTime, UNIX_EPOCH}};
use sha2::{Sha256, Sha512, Digest};
use base64::encode;

pub fn time_now()->u64{
    return SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();   
}
pub fn nonce()->u32{
    let mut rng = rand::rng(); // Create a random number generator
    return rng.random_range(1..=1_000_000_000); //
}

pub fn hash_and_encode(data: String) -> String {
    let mut hasher = Sha256::new();

   
    hasher.update(data.as_str().as_bytes());

    // Read hash digest and consume hasher
    let hashed_data = hasher.finalize();

    // Encode the hashed data to Base64 and convert to String
    let encoded_data = encode(&hashed_data);
    encoded_data
}

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