use std::fs::File;
use std::io::Read;
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{pkey::PKey, rsa::{Padding, Rsa}, x509::X509};

#[allow(unused)]


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

#[allow(unused)]
pub fn encrypt_with_cert(cert_pem: &str, data: &str) -> Result<String, Box<dyn std::error::Error>> {
    let cert = X509::from_pem(cert_pem.as_bytes())?;
    let pub_key = cert.public_key()?;
    let rsa = pub_key.rsa()?;

    let mut encrypted = vec![0; rsa.size() as usize];
    rsa.public_encrypt(data.as_bytes(), &mut encrypted, Padding::PKCS1)?;

    Ok(STANDARD.encode(encrypted))
}
