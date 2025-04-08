use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::{env, thread};
use std::{fs::File, io::BufReader, time::SystemTime};
use base64::{decode,encode};
use openssl::rsa::{Padding, Rsa};
use client_server_functions::server_function::{split, Server};
mod client_server_functions;

enum ClientState{
    Authenticating,
    Authenticated,
}


fn handle_client(mut stream: TcpStream, clients: Arc<Mutex<Vec<TcpStream>>>,server:Server) {
    //Stream buffer to store incomming messages
    let mut buffer = [0; 512];
    // let mut cipher_text=Vec::new();
    // let mut signed_hash=Vec::new();

    let mut client_state = ClientState::Authenticating;

    loop {
        
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("Client disconnected.");
                break;
            }
            //read buffer if there is any data
            Ok(n) => {
                match client_state {
                    ClientState::Authenticating =>{
                        let auth_data = String::from_utf8_lossy(&buffer[..n]);
                        let (cipher_text,hash_signed,_nothing)=split(auth_data.to_string()).unwrap();
                        println!("Server Cipher: {}",cipher_text);
                        println!("Server Hash: {}",hash_signed);

                        client_state = ClientState::Authenticated;

                    }
                    ClientState::Authenticated =>{
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
        }
                //cert creation or setup
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
    let args:Vec<String> =env::args().collect();
    let server_name =args.get(1).cloned().unwrap_or_else(|| "test_server".to_string());
    let listener = TcpListener::bind("127.0.0.1:34254")?;
    println!("Server is running on 127.0.0.1:34254");
    let server_entity=Server::new(server_name.clone());
    


    let clients = Arc::new(Mutex::new(Vec::new())); // Shared list of clients

    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connecting... {:?}", stream.peer_addr());

                let clients_clone = Arc::clone(&clients);
                let server_clone=server_entity.clone();
                clients.lock().unwrap().push(stream.try_clone().unwrap());

                thread::spawn(move || handle_client(stream, clients_clone,server_clone));
            }
            Err(_) => eprintln!("Connection failed"),
        }
    }
    Ok(())
}
