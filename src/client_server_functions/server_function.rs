use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use super::decryption_module::private_key_decrypt;
use super::decryption_module::public_key_decrypt;
use super::encryption_module;
use super::decryption_module;

pub fn split(text: String) -> Option<(String, String, Option<String>)> {
    let parts: Vec<&str> = text.split("||").collect();
    
    match parts.len() {
        2 => Some((parts[0].to_string(), parts[1].to_string(), None)),
        3 => Some((parts[0].to_string(), parts[1].to_string(), Some(parts[2].to_string()))),
        _ => None, // Return None if the text doesn't split into exactly two or three parts
    }
}

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

#[derive(Clone)]
pub struct Server{
    server_name:String,
}
impl Server{
    pub fn new(server_name:String)->Self{Self{server_name}}
    
    pub fn authenticate_user_data(&self,cipher_text:String,signed_hash:String)->Result<(String,String,String),String>{
    let decrypted_data=private_key_decrypt(cipher_text, self.server_name.clone());
    let (_nonce,_time,_username)=split(decrypted_data).unwrap();

    /*IF TIME IS LESS THAN A DAY AND NONCE IS VALID AND hash(decrypted)=unsigned(SIGNED_HASH)
    [
        RETURN INFO BELOW
    ] */
        
        return Ok(
            ("nonce".to_string(),
             "time".to_string(),
             "username".to_string()
            )
        );
    }
    
    
    
}