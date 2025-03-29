use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
mod cert_mod;
use std::{fs::File, io::BufReader, time::SystemTime};
use base64::{decode,encode};
use openssl::rsa::{Padding, Rsa};



fn handle_client(mut stream: TcpStream, clients: Arc<Mutex<Vec<TcpStream>>>) {
    //Stream buffer to store incomming messages
    let mut buffer = [0; 512];

    //decrpyt
    let mut intial_buffer = [0;512];
    stream.read(&mut intial_buffer).unwrap();
    let intial_data=String::from_utf8_lossy(&intial_buffer).to_string();
    let parts: Vec<&str> = intial_data.split("||").collect();

    let data = parts[0].to_string();
    let hash = parts[1].to_string();
    println!("-----------------DATA-----------------------");
    println!("{}",data);
    println!("-----------------HASH-----------------------");
    println!("{}",hash);
    
    //get intial data from stream
    use cert_mod::decrypt_encrypt::{decrypted_data,hash_and_encode,_verifcation};
    
    //decrpyt data by server with its private key 
    let decrypted_data_=decrypted_data("test_server".to_string(), cert_mod::decrypt_encrypt::operation_type::Authentication, data);
    
    //hash to compare with signed hash
    let decrypted_data_hash_=hash_and_encode(decrypted_data_.clone());

    


    //Client verification
    if _verifcation(decrypted_data_.clone()).is_ok(){
        stream.write_all(b"Connection accepted").unwrap();
    } else {
        stream.write_all(b"Connection rejected").unwrap();
        return;

    }
    


    loop {
        
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("Client disconnected.");
                break;
            }
            //read buffer if there is any data
            Ok(n) => {
                //cert creation or setup
                let message = String::from_utf8_lossy(&buffer[..n]);
                println!("{}", message);

                // Broadcast message to all connected clients
                let mut clients_lock = clients.lock().unwrap();
                clients_lock.retain(|s| !s.peer_addr().is_err()); // Remove disconnected clients

                for client in clients_lock.iter_mut() {
                    if client.peer_addr().ok() != stream.peer_addr().ok() {
                        // Avoid echoing to sender  
                        if let Err(e) = client.write_all(message.as_bytes()) {
                            eprintln!("Failed to send message: {}", e);
                        }
                    }
                }
            }
            Err(_) => {
                println!("Client connection error.");
                break;
            }
        }
    }

    // Remove client from the list when it disconnects
    let mut clients_lock = clients.lock().unwrap();
    clients_lock.retain(|s| s.peer_addr().ok() != stream.peer_addr().ok());

    println!("Client removed.");
}



fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:34254")?;
    println!("Server is running on 127.0.0.1:34254");

    //Key genration
    let rsa=Rsa::generate(2048)?;

    //private key storage
    let private_key_pem = rsa.private_key_to_pem()?;
    let mut file = File::create("src/server_private_key.pem").expect("Failed to write to file");
    file.write_all(&private_key_pem).expect("Failed to write private key");
    

    //public key generation
    let n = rsa.n().to_owned()?; // Modulus
    let e = rsa.e().to_owned()?; // Exponent
    let rsa_public = Rsa::from_public_components(n, e)?;

    //public key storage
    let public_key_pem=rsa_public.public_key_to_pem()?;
    let mut file = File::create("src/server_public_key.pem").expect("Failed to write to file");
    file.write_all(&public_key_pem).expect("Failed to write public key");



    let clients = Arc::new(Mutex::new(Vec::new())); // Shared list of clients

    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connecting... {:?}", stream.peer_addr());

                let clients_clone = Arc::clone(&clients);
                clients.lock().unwrap().push(stream.try_clone().unwrap());

                thread::spawn(move || handle_client(stream, clients_clone));
            }
            Err(_) => eprintln!("Connection failed"),
        }
    }
    Ok(())
}
