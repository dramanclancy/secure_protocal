use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::{env, thread};
use client_server_functions::utilities_functions::{self, generate_cert_from_pem, ClientMessage};
use client_server_functions::server_function::{split, Server};
mod client_server_functions;
use serde_json;
use std::io::{BufReader, BufRead};


enum ClientState{
    Authenticating,
    Authenticated
}
use std::io::ErrorKind;


fn drain_stream(stream: &mut TcpStream, buffer: &mut [u8]) {
    // Set to non-blocking mode
    if let Err(e) = stream.set_nonblocking(true) {
        eprintln!("Failed to set non-blocking: {}", e);
        return;
    }

    loop {
        match stream.read(buffer) {
            Ok(0) => break, // connection closed
            Ok(_) => continue, // more data to drain
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break, // no more data
            Err(e) => {
                eprintln!("Error while draining stream: {}", e);
                break;
            }
        }
    }

    // Restore blocking mode
    if let Err(e) = stream.set_nonblocking(false) {
        eprintln!("Failed to reset blocking mode: {}", e);
    }

    // Optional: clear buffer after drain
    buffer.fill(0);
}

#[allow(unused)]
fn handle_client(mut stream: TcpStream, clients: Arc<Mutex<Vec<TcpStream>>>,server:Server) {
    //Stream buffer to store incomming messages
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    // let mut cipher_text=Vec::new();
    // let mut signed_hash=Vec::new();

    let mut client_state = ClientState::Authenticating;
    let mut count = clients.lock().unwrap().len();
    let mut authenticated_username: Option<String> = None; // <-- add this line
    
    
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                println!("Client disconnected.");
                break;
            }
            Ok(_) => {
                let mut clients_lock = clients.lock().unwrap();
                match client_state {
                    ClientState::Authenticating => {
                        let auth_data = line.trim_end(); // Remove trailing \n
                        let (cipher_text, signed_hash, _nothing) = split(auth_data.to_string()).unwrap();
    
                        let auth_bool = server.authenticate_user_data(cipher_text, signed_hash);
                        if auth_bool.is_ok() {
                            if count > 1 {
                                println!("{}", count);
    
                                let (_, _, user_name) = auth_bool.unwrap();
                                authenticated_username = Some(user_name.clone());
                                let user_cert = generate_cert_from_pem(&user_name);
                                let pem_bytes = user_cert.to_pem().unwrap();
                                let pem_string = String::from_utf8(pem_bytes).unwrap();
                                println!("cert:\n{}", pem_string);
    
                                let user_data = utilities_functions::OnlineUserData {
                                    user_name,
                                    certificate: pem_string,
                                };
    
                                let x = utilities_functions::ClientMessage::KeyExchange { user_data };
                                for client in clients_lock.iter_mut() {
                                    let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                                    if client.peer_addr().ok() != reader.get_ref().peer_addr().ok() {
                                        if let Err(e) = client.write_all(serialized.as_bytes()) {
                                            eprintln!("Failed to send message: {}", e);
                                        }
                                    }
                                }
                            }
    
                            client_state = ClientState::Authenticated;
                        } else {
                            println!("Could not Authenticate User......");
                            break;
                        }
                    }
    
                    ClientState::Authenticated => {
                        let message = line.trim_end().to_string();
                        let user_name = authenticated_username
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string());
    
                        println!("{}: {}", user_name, message);
    
                        clients_lock.retain(|s| !s.peer_addr().is_err());
    
                        for client in clients_lock.iter_mut() {
                            let x = utilities_functions::ClientMessage::TextMessage {
                                user_name: user_name.clone(),
                                text: message.clone(),
                            };
    
                            let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                            if client.peer_addr().ok() != reader.get_ref().peer_addr().ok() {
                                if let Err(e) = client.write_all(serialized.as_bytes()) {
                                    eprintln!("Failed to send message: {}", e);
                                }
                            }
                        }
                    }
                }
            }
    
            Err(e) => {
                eprintln!("Client read error: {}", e);
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
