use std::fs::File;
use std::io::Read;
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::rsa::{Padding, Rsa};

#[allow(unused)]
pub fn public_key_encrypt( plaintext:String,entity:String) ->String{
    //Get public key file
    let file_dir=format!("src/pem/{}_public_key.pem",entity);
    let mut public_key_file = File::open(file_dir).expect("Failed to open public key file");
    let mut public_pem = String::new();
    public_key_file.read_to_string(&mut public_pem).expect("Failed to read public key file");


    //Public key 
    let public_key = Rsa::public_key_from_pem(public_pem.as_bytes()).expect("Failed to parse public key");


    //Buffer for encrypted data 
    let mut encrypted_data = vec![0; public_key.size() as usize];


    //Encrpytion
    public_key.public_encrypt(plaintext.as_bytes(), &mut encrypted_data, Padding::PKCS1).expect("Failed to encrypt data");


    //Encoded for transmission
    let encrypted_data_as_string = STANDARD.encode(&encrypted_data);


    return encrypted_data_as_string;
}

#[allow(unused)]
pub fn private_key_encrypt(plain_text:String,entity:String)->String{
    let file_dir=format!("src/pem/{}_private_key.pem",entity);
    let mut private_key_file = File::open(file_dir).expect("Failed to open public key file");
    let mut private_pem = String::new();
    private_key_file.read_to_string(&mut private_pem).expect("Failed to read public key file");


    //Private key 
    let private_key = Rsa::private_key_from_pem(private_pem.as_bytes()).expect("Failed to parse public key");


    //buffer for encrypted data 
    let mut encrypted_data = vec![0; private_key.size() as usize];


    //Encrpytion
    private_key.private_encrypt(plain_text.as_bytes(), &mut encrypted_data, Padding::PKCS1).expect("Failed to encrypt data");


    //Encoded for transmission
    let encrypted_data_as_string = STANDARD.encode(&encrypted_data);


    return encrypted_data_as_string;
}