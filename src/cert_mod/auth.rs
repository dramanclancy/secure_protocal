use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};
use rand::Rng as _;
use rcgen::PublicKey;
use std::time::UNIX_EPOCH;
use std::{fs::File, io::BufReader, time::SystemTime};
use std::io::{self, Read, Write};
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
    pub fn auth_data(&self)->String{
        //get current time
        let sys_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let x=format!("{}",sys_time.as_secs());

        //Random nonce
        let mut rng = rand::rng(); // Create a random number generator
        let random_number = rng.random_range(1..=1_000_000_000); // Generate a number between 1 and 1,000,000
        println!("Random number: {}", random_number);

        //Username
        println!("{}",self.username);

        //contatinat
        let data=format!("{}||{}||{}",x,random_number,self.username);
        println!("{}",data);
        //entceypt with server public key 

        //hass conctinated data
        //sign buy enctortying with private key

        //runn test 



        // let mut server_public_key_file=File::open("src/server_public_key.pem").unwrap();
        // let mut server_pem=String::new();
        // server_public_key_file.read_to_string(&mut server_pem).unwrap();

        // let pbkey=Rsa::public_key_from_pem(server_pem.as_bytes()).unwrap();
        // let mut encrpted_data: &[u8]=;
        // pbkey.public_encrypt(data.as_bytes(), &mut encrpted_data, Padding::PKCS1);
        // encrpted_data.to_ascii_lowercase();
        return data;
    }
    //fn encryption()->String{}
    //fn decryption()->String{}
    //fn session()->String{}
}