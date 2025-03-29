use openssl::rsa::{Padding, Rsa};
use rand::Rng as _;
use std::time::UNIX_EPOCH;
use std::{fs::File, io::BufReader, time::SystemTime,io::{self, Read, Write}};
use base64::encode;
use sha2::{Sha256, Sha512, Digest};
use super::decrypt_encrypt;
use decrypt_encrypt::{encrypt_data,operation_type,hash_and_encode};




fn public_key_encryption(){}
pub struct Entity {
    pub username:String,
    //pub public_key:Rsa<Public>,
    //private_key:Rsa<Private>
}

impl Entity{
    //entitiy creation creates Public key and private key 
    pub fn new(username:String)->Self{
        let rsa=Rsa::generate(2048).expect("Private Key was not generated");
        
        //private key storage
        let  private_key_pem= rsa.private_key_to_pem().expect("Coversion of Private Key to String Failed");
        let private_file_path=format!("src/auth_cert/{}_private_key.pem",username);
        let mut file= File::create(&private_file_path).expect("Failed to write to file");
        file.write_all(&private_key_pem).expect("Failed to write private key");
        println!("------------------------------------------------------------------------");
        println!("Private Key Creation Success");

        //public key generation
        let n = rsa.n().to_owned().unwrap(); // Modulus
        let e = rsa.e().to_owned().unwrap(); // Exponent
        let rsa_public = Rsa::from_public_components(n, e).unwrap();

        //public key storage
        let public_key_pem=rsa_public.public_key_to_pem().expect("Failed to create public key");
        let public_file_path=format!("src/auth_cert/{}_public_key.pem",username);
        let mut file = File::create(public_file_path).expect("Failed to write to file");
        file.write_all(&public_key_pem).expect("Failed to write public key");
        println!("------------------------------------------------------------------------");
        println!("Private Key Creation Success");
        let pbk=Rsa::public_key_from_pem(&public_key_pem).unwrap();
        let pvk=Rsa::private_key_from_pem(&private_key_pem).unwrap();
        Self { username}

    }  
    
    //function to create auth message for given entity
    pub fn auth_data(&self)->(String,String){

        //get current time in seconds since 1970
        let sys_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let x=format!("{}",sys_time.as_secs());

        //Random nonce
        let mut rng = rand::rng(); // Create a random number generator
        let random_number = rng.random_range(1..=1_000_000_000); // Generate a number between 1 and 1,000,000
      
//auth mesaage constructuion
        //Concatenate data
        let data=format!("{}||{}||{}",x,random_number,self.username);
        println!("{}",data);
        //ENCRYPT
        let encrypted_data_as_string=encrypt_data(String::from("test_server"), String::from("clancy"), operation_type::authentication, data.clone());
        let hashed_data=hash_and_encode(data.clone());
        let hashed_signed_data=
        return (encrypted_data_as_string,hashed_data);
    }
    //fn encryption()->String{}
    //fn decryption()->String{}
    //fn session()->String{}
}