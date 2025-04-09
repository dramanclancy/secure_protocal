use core::hash;

use crate::client_server_functions::utilities_functions::nonce;
use crate::client_server_functions::utilities_functions::time_now;

use super::encryption_module;
use super::utilities_functions::hash_and_encode;

#[allow(unused)]
pub struct Client {
    username: String,
    server_name: String,
}

#[allow(unused)]
impl Client {
    pub fn new(username: String, server_name: String) -> Self {
        Self { username, server_name }
    }

    pub fn authentication_data(&self, plain_text: String) -> (String,String) {
        let _time=time_now();
        let _nonce=nonce();
        let data=format!("{}||{}||{}",_nonce,_time,self.username);
        let cipher_text = encryption_module::public_key_encrypt(data.clone(), self.server_name.clone());
        let hash=hash_and_encode(data);
        let signed_hash=encryption_module::private_key_encrypt(hash.clone(), self.username.clone());
        (cipher_text,signed_hash)
    }
    

}
