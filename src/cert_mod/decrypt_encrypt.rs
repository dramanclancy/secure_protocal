use openssl::rsa::{Padding, Rsa};
use rand::Rng as _;
use std::time::UNIX_EPOCH;
use std::{fs::File, io::BufReader, time::SystemTime,io::{self, Read, Write}};
use base64::{decode,encode};
use sha2::{Sha256, Sha512, Digest};
use super::decrypt_encrypt;

pub enum  operation_type{
    authentication,
    message_transfer
    
}

pub fn hash_and_encode(data: String) -> String {
    let mut hasher = Sha256::new();

    // Write input message
    hasher.update(data.as_str().as_bytes());

    // Read hash digest and consume hasher
    let hashed_data = hasher.finalize();

    // Encode the hashed data to Base64 and convert to String
    let encoded_data = encode(&hashed_data);
    encoded_data
}

/*

*/
pub fn encrypt_data(for_entity:String,username:String,encrypt_type:operation_type,data:String,)->String{
    // Encrypting data with Server public key 
    //for_entity=test_server
    //for_entity=B or C
    match encrypt_type{
        operation_type::authentication=>{
            //Get public key file
            let file_dir=format!("src/{}_public_key.pem",for_entity);
            let mut public_key_file = File::open(file_dir).expect("Failed to open public key file");
            let mut public_pem = String::new();
            public_key_file.read_to_string(&mut public_pem).expect("Failed to read public key file");


            //Public key 
            let public_key = Rsa::public_key_from_pem(public_pem.as_bytes()).expect("Failed to parse public key");
            
            
            //Buffer for encrypted data 
            let mut encrypted_data = vec![0; public_key.size() as usize];
            
            
            //Encrpytion
            public_key.public_encrypt(data.as_bytes(), &mut encrypted_data, Padding::PKCS1).expect("Failed to encrypt data");
             
             
            //Encoded for transmission
            let encrypted_data_as_string = encode(&encrypted_data);


            return encrypted_data_as_string;
        }

        operation_type::message_transfer=>{
            let file_dir=format!("src/{}_private_key.pem",username);
            let mut private_key_file = File::open(file_dir).expect("Failed to open public key file");
            let mut private_pem = String::new();
            private_key_file.read_to_string(&mut private_pem).expect("Failed to read public key file");

    
            //Private key 
            let private_key = Rsa::private_key_from_pem(private_pem.as_bytes()).expect("Failed to parse public key");
    

            //buffer for encrypted data 
            let mut encrypted_data = vec![0; private_key.size() as usize];
    

            //Encrpytion
            private_key.private_encrypt(data.as_bytes(), &mut encrypted_data, Padding::PKCS1).expect("Failed to encrypt data");
    

            //Encoded for transmission
            let encrypted_data_as_string = encode(&encrypted_data);


            return encrypted_data_as_string;
        }
    }
   

}

pub fn decrypted_data(from_entity:String,username:String,decrypt_type:operation_type,data: String)->String{
    // Read server private key
    match decrypt_type{
    operation_type::authentication=>{
        let file_dir=format!("src/{}_private_key.pem",username);
        let mut private_key_file = File::open("src/test_server_private_key.pem").expect("Failed to open private key file");
        let mut private_pem = String::new();
        private_key_file.read_to_string(&mut private_pem).expect("Failed to read private key file");

        let private_key = Rsa::private_key_from_pem(private_pem.as_bytes()).expect("Failed to parse private key");

        //decoding transmitted data to binary
        let encrypted_data_bytes = decode(data).expect("Failed to decode encrypted data");

        //buffer for decrypted data
        let mut decrypted_data = vec![0; private_key.size() as usize];

        //decryption
        private_key.private_decrypt(&encrypted_data_bytes, &mut decrypted_data, Padding::PKCS1).expect("Failed to decrypt data");

        // Trim trailing zeros and print decrypted data
        if let Some(pos) = decrypted_data.iter().rposition(|&x| x != 0) {
        decrypted_data.truncate(pos + 1);
        }
        println!("---------------DECRYPTED MESSAGE---------------------------");
        println!("{}", String::from_utf8_lossy(&decrypted_data));
        //convert to string
        
        return String::from_utf8(decrypted_data).unwrap();
        }
        operation_type::message_transfer=>{
            return String::from("test");
        }
    }

}

fn sign_data(){

}

fn verify_data(){

}