use core::hash;
use std::fs;
use std::io::Read;

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::sign::Verifier;

use crate::client_server_functions::utilities_functions::nonce;
use crate::client_server_functions::utilities_functions::time_now;

use super::encryption_module;
use super::encryption_module::encrypt_with_cert;
use super::utilities_functions::hash_and_encode;
use super::utilities_functions::sign_message;

///Retrives cert from storage based on username
pub fn get_cert(entity: &str) -> String {
    ///path creation
    let path = format!("src/pem/{}_cert.pem", entity);
    let mut file = fs::File::open(&path).expect("Certificate file not found");
    let mut cert_pem = String::new();
    file.read_to_string(&mut cert_pem).expect("Failed to read certificate");
    cert_pem
}

#[allow(unused)]
pub struct Client {
    username: String,
    server_name: String,
}

pub enum ClientInput {
    GetCertificates,
    ListOnlineUsers,
    SendRndNumber,
    CreateNewSession,
    DiplayMenu
}




#[allow(unused)]
impl Client {
    pub fn new(username: String, server_name: String) -> Self {
        Self { username, server_name }
    }

    pub fn authentication_data(&self, plain_text: String,) -> (String,String,String) {
        let _time=time_now();
        let _nonce=nonce();
        let data=format!("{}||{}||{}",_nonce,_time,self.username);
        let server_cert=get_cert(&self.server_name);
        let cipher_text=encrypt_with_cert(&server_cert, &data).unwrap();
        let hash=hash_and_encode(data);
        let hash_signature=sign_message(&hash, &self.username);
        (cipher_text,hash_signature,hash)
    }


}