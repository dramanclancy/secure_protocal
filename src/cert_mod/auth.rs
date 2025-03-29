use openssl::rsa::{Padding, Rsa};
use rand::Rng as _;
use std::time::UNIX_EPOCH;
use std::{fs::File, io::BufReader, time::SystemTime,io::{self, Read, Write}};
use base64::encode;

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
    pub fn auth_data(&self)->(String,String){
        //get current time
        let sys_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let x=format!("{}",sys_time.as_secs());

        //Random nonce
        let mut rng = rand::rng(); // Create a random number generator
        let random_number = rng.random_range(1..=1_000_000_000); // Generate a number between 1 and 1,000,000
        //println!("Random number: {}", random_number);

        //Username
        //println!("{}",self.username);

        //contatinat
        let data=format!("{}||{}||{}",x,random_number,self.username);
        println!("{}",data);
        //entceypt with server public key 

        //hass conctinated data
        //sign buy enctortying with private key

        //runn test 



        

        // Read server public key
        let mut server_public_key_file = File::open("src/test_server_public_key.pem").expect("Failed to open public key file");
        let mut server_pem = String::new();
        server_public_key_file.read_to_string(&mut server_pem).expect("Failed to read public key file");
    
        let pbkey = Rsa::public_key_from_pem(server_pem.as_bytes()).expect("Failed to parse public key");

        //buffer for encrypted data 
        let mut encrypted_data = vec![0; pbkey.size() as usize];

        //encrpytion
        pbkey.public_encrypt(data.as_bytes(), &mut encrypted_data, Padding::PKCS1).expect("Failed to encrypt data");
    
        //encoded for transmission
        let encrypted_data_as_string = encode(&encrypted_data);
       
        
       
    
        
        
        //Hashing

        
        return (encrypted_data_as_string,data);
    }
    //fn encryption()->String{}
    //fn decryption()->String{}
    //fn session()->String{}
}