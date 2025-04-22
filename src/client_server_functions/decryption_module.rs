use std::fs::File;
use std::io::Read;
use openssl::rsa::{Padding, Rsa};
use base64::{engine::general_purpose::STANDARD, Engine};

///uses public key to decrypt
#[allow(unused)]
pub fn public_key_decrypt( cipher_text:String,entity:String) ->String{
    let file_dir=format!("src/pem/{}_public_key.pem",entity);
    let mut public_key_file = File::open(file_dir).expect("Failed to open private key file");
    let mut public_pem = String::new();
    
    public_key_file.read_to_string(&mut public_pem).expect("Failed to read private key file");

    let public_key = Rsa::public_key_from_pem(public_pem.as_bytes()).expect("Failed to parse private key");

    //decoding transmitted data to binary
    let encrypted_data_bytes = STANDARD.decode(cipher_text).expect("Failed to decode encrypted data");

    //buffer for decrypted data
    let mut decrypted_data = vec![0; public_key.size() as usize];

    //decryption
    public_key.public_decrypt(&encrypted_data_bytes, &mut decrypted_data, Padding::PKCS1).expect("Failed to decrypt data");

    // Trim trailing zeros and print decrypted data
    if let Some(pos) = decrypted_data.iter().rposition(|&x| x != 0) {
        decrypted_data.truncate(pos + 1);
    }
    return String::from_utf8(decrypted_data).unwrap();
}

///uses private key to decrypt
pub fn private_key_decrypt(cipher_text:String,entity:String)->String{
    let file_dir=format!("src/pem/{}_private_key.pem",entity);
    let mut private_key_file = File::open(file_dir).expect("Failed to open private key file");
    let mut private_pem = String::new();
    private_key_file.read_to_string(&mut private_pem).expect("Failed to read private key file");

    let private_key = Rsa::private_key_from_pem(private_pem.as_bytes()).expect("Failed to parse private key");

    //decoding transmitted data to binarydata
    let encrypted_data_bytes = STANDARD.decode(cipher_text).expect("Failed to decode encrypted data");

    //buffer for decrypted data
    let mut decrypted_data = vec![0; private_key.size() as usize];

    //decryption
    private_key.private_decrypt(&encrypted_data_bytes, &mut decrypted_data, Padding::PKCS1).expect("Failed to decrypt data");

    // Trim trailing zeros and print decrypted data
    if let Some(pos) = decrypted_data.iter().rposition(|&x| x != 0) {
        decrypted_data.truncate(pos + 1);
    }
    return String::from_utf8(decrypted_data).unwrap();
}