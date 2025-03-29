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

    let encrypted_data_as_string=String::from("Msd41/Xo50hQVEKkpazudFwMRJ/lZ0Zxj9Sr/V6srfryFm6yBw0MTgTkL3u/IyEbDGxBLLshs/TXCwv0yqx7WshwfUxod4nGSh4Ke19mxjzzZxtAYs6auQcTEKGdRtUOzqRtAVb5zaOv+D8gRncCbmtp117lSpimsLZ67iEqkKZ62/BkYBAtkXFB3eyXgtHa0VexeuL21cE0oe4gAroVTan1G2sOvmyNPO3Q6p9CcqmHbCPle7l6wWtl+tmXDeLn1LP29+Efo/xPaL7+fWG5tqew8m8gdL+IDkyPbTsetJ4FmV0MDsTi8ZePZtuOBwWcjbczpi0TeYVBY3sNO4YIMA==");
    //Decrpyt
    use cert_mod::decrypt_encrypt::{operation_type,decrypted_data};
    let decrypted_data_as_string=decrypted_data(String::from("test_server"), String::from("test_server"), operation_type::authentication, encrypted_data_as_string.clone());
    println!("decrypted_data:{}",decrypted_data_as_string);
    
/*if (meassage is struct ):
                    convert bytes to string and output
                    extract auth_data
                    run decrypt 
                    if (Ok()):
                        CONTIUNE


                    else:
                        break;
                else: 
                    convert bytes to string and output
                    */

    //case to chea=ck if the buffer has any data

// Authentication passed, add client to the list
    /*
    {
        let mut clients_lock = clients.lock().unwrap();
        clients_lock.push(stream.try_clone().unwrap());
    }
    */


// let id_file=File::open("src/user_id.txt").unwrap();
// let reader=io::BufReader::new(id_file);
// for line in reader.lines(){

// }

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
                println!("New client connected: {:?}", stream.peer_addr());

                let clients_clone = Arc::clone(&clients);
                clients.lock().unwrap().push(stream.try_clone().unwrap());

                thread::spawn(move || handle_client(stream, clients_clone));
            }
            Err(_) => eprintln!("Connection failed"),
        }
    }
    Ok(())
}
