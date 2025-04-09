use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;



use super::decryption_module::private_key_decrypt;
use super::utilities_functions;

#[allow(unused)]
pub fn split(text: String) -> Option<(String, String, Option<String>)> {
    let parts: Vec<&str> = text.split("||").collect();
    
    match parts.len() {
        2 => Some((parts[0].to_string(), parts[1].to_string(), None)),
        3 => Some((parts[0].to_string(), parts[1].to_string(), Some(parts[2].to_string()))),
        _ => None, // Return None if the text doesn't split into exactly two or three parts
    }
}
#[allow(unused)]
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

fn verify_nonce(nonce:String)->Result<(),String>{
    let file_dir=format!("src/nonce.txt");
    let mut nonce_file = File::open(file_dir).expect("Failed to open nonce file");
    let reader = BufReader::new(nonce_file);
    // Read the file line by line
    for line in reader.lines() {
        match line {
            Ok(line) => {
                if line.trim() == nonce {
                    return Err("Nonce already used".to_string());
                }

            },
            Err(error) => eprintln!("Error reading line: {}", error),
        }
    }
    let mut file = OpenOptions::new()
    .append(true)
    .create(true)
    .open("src/nonce.txt")
    .map_err(|e| format!("Failed to open file for appending: {}", e))?;

    writeln!(file, "{}", nonce).map_err(|e| format!("Failed to write nonce: {}", e))?;
        return Ok(())
}

fn verify_hash(decrypted_data:String,signed_hash:String)->Result<(),String>{
    return Ok(())
}

#[derive(Clone)]
#[allow(unused)]
pub struct Server{
    server_name:String,
}

#[allow(unused)]
impl Server{
    pub fn new(server_name:String)->Self{Self{server_name}}
    
    pub fn authenticate_user_data(&self,cipher_text:String,signed_hash:String)->Result<(String,String,String),String>{
    let decrypted_data=private_key_decrypt(cipher_text, self.server_name.clone());
    let (_nonce,_time,_username)=split(decrypted_data.clone()).unwrap();
    
    let time_valid_status= verify_time(_time.clone()).is_ok();
    let nonce_valid_status=verify_nonce(_nonce.clone()).is_ok();
    let hash_valid_status=verify_hash(decrypted_data,signed_hash).is_ok();
    
    

    if(time_valid_status&&nonce_valid_status&&hash_valid_status){
        return Ok(
            (_nonce,
             _time,
             _username.unwrap()
            )
        );
    }else{
        Err("Couldnt authenticate".to_string())
    }
        
        
    }
    
    
    
}