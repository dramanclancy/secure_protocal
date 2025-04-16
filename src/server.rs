use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::{env, thread};

use base64::{engine::general_purpose::STANDARD, Engine};
use client_server_functions::client_function::get_cert;
use client_server_functions::encryption_module::private_key_encrypt;
use client_server_functions::server_function::{split, Client, Server};
use client_server_functions::utilities_functions::{
    self, create_new_key_private_key, generate_cert_from_pem, MessageToClient, MessageToServer,
};
use openssl::pkey::PKey;
use serde_json;
use std::collections::HashMap;
use std::io::ErrorKind;

mod client_server_functions;

enum ClientState {
    Authenticating,
    Authenticated,
}

fn get_menu() -> String {
    "---------------------MENU-----------------------
-s: get unpulled cert from cer
-l: list online user
-o: send random number for pulled certs
-k: create session key for stored session keys
-u: update session key
-m: display menu
-q: quit
----------------------------------------------------"
        .to_string()
}

fn send_menu(stream: &mut TcpStream, cert_registry: &HashMap<String, Client>, sender: &str) {
    let menu = get_menu();

    let mut online_list = String::from("Online: ");
    for (username, client) in cert_registry.iter() {
        online_list.push_str(&format!("{}:{}, ", username, client.port));
    }
    if online_list.ends_with(", ") {
        online_list.truncate(online_list.len() - 2);
    }

    let full_message = format!("{}\n{}\n", menu, online_list);

    let wrapped = MessageToClient::PlainTextMessage {
        user_name: sender.to_string(),
        text: full_message,
    };

    let serialized = format!("{}\n", serde_json::to_string(&wrapped).unwrap());

    if let Err(e) = stream.write_all(serialized.as_bytes()) {
        eprintln!("Failed to send menu: {}", e);
    }
}

fn handle_client(
    mut stream: TcpStream,
    clients: Arc<Mutex<Vec<TcpStream>>>,
    server: Server,
    cert_registry: Arc<Mutex<HashMap<String, Client>>>,
    randomNumber: Arc<Mutex<HashMap<String, HashMap<String, (String, String)>>>>,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    let rndNoHash = randomNumber;
    let mut client_state = ClientState::Authenticating;
    let mut authenticated_username: Option<String> = None;

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
                        let auth_data = line.trim_end();
                        let (cipher_text, hash_signature, hash) =
                            split(auth_data.to_string()).unwrap();
                        let auth_bool = server.authenticate_user_data(
                            cipher_text.clone(),
                            hash_signature.clone(),
                            hash.unwrap().clone(),
                        );
                        if let Ok((_, _, user_name)) = auth_bool {
                            println!("[INFO] Client '{}' authenticated", user_name);
                            authenticated_username = Some(user_name.clone());
                            let cert = get_cert(&user_name);
                            let port = reader.get_ref().peer_addr().unwrap().port().to_string();
                            let client_cert_data = Client {
                                user_name: user_name.clone(),
                                cert,
                                port,
                            };
                            cert_registry
                                .lock()
                                .unwrap()
                                .insert(user_name.clone(), client_cert_data);
                            let registry_guard = cert_registry.lock().unwrap();
                            send_menu(&mut stream, &registry_guard, &user_name);

                            client_state = ClientState::Authenticated;
                        } else {
                            println!("[WARN] Failed to authenticate client.");
                            break;
                        }
                    }
                    ClientState::Authenticated => {
                        let message = line.trim_end().to_string();
                        println!("[RECV] Message: {}", message);
                        println!("----------------------------------------");

                        match serde_json::from_str::<MessageToServer>(&message) {
                            Ok(MessageToServer::GetCerts { user_name }) => {
                                println!("[INFO] {} requested certificates", user_name);
                                let mut cert = HashMap::<String, String>::new();
                                let registry_guard = cert_registry.lock().unwrap();
                                let auth_username =
                                    authenticated_username.clone().unwrap_or_default();

                                for (username, client) in registry_guard.iter() {
                                    if username != &auth_username {
                                        cert.insert(username.clone(), client.cert.clone());
                                    }
                                }

                                let certificate = MessageToClient::CertHashMap { cert };
                                let serialized =
                                    format!("{}\n", serde_json::to_string(&certificate).unwrap());

                                if let Err(e) = stream.write_all(serialized.as_bytes()) {
                                    eprintln!("[ERROR] Failed to send certs: {}", e);
                                }
                            }

                            Ok(MessageToServer::SendRndNos {
                                encrypted_rnd_no,
                                rnd_no_signature,
                                forclient,
                            }) => {
                                let sender = authenticated_username.clone().unwrap_or_default();
                                let recipient = forclient;

                                let mut rnd_map = rndNoHash.lock().unwrap();
                                let entry = rnd_map
                                    .entry(recipient.clone())
                                    .or_insert_with(HashMap::new);
                                entry.insert(
                                    sender.clone(),
                                    (encrypted_rnd_no.clone(), rnd_no_signature.clone()),
                                );

                                println!(
                                    "[INFO] Stored random number from '{}' → '{}'",
                                    sender, recipient
                                );

                                // Debug print current state of all random numbers
                                println!("---------- [DEBUG] rndNoHash State ----------");
                                for (rcpt, inner_map) in rnd_map.iter() {
                                    println!("Recipient: {}", rcpt);
                                    for (sndr, (rnd, sig)) in inner_map.iter() {
                                        println!("  <- From {}:", sndr);
                                        println!(
                                            "     Encrypted RND: {}...",
                                            &rnd[..15.min(rnd.len())]
                                        );
                                        println!(
                                            "     Signature     : {}...",
                                            &sig[..15.min(sig.len())]
                                        );
                                    }
                                }
                                println!("---------------------------------------------");
                            }

                            Ok(MessageToServer::CreateNewSsessionKeys { uname }) => {
                                println!(
                                    "[INFO] Creating session key for '{}'. Collecting random numbers...",
                                    uname
                                );

                                let rnd_map = rndNoHash.lock().unwrap();

                                if let Some(inner_map) = rnd_map.get(&uname) {
                                    println!(
                                        "[INFO] Found {} random numbers for '{}':",
                                        inner_map.len(),
                                        uname
                                    );
                                    for (sender, (rnd, sig)) in inner_map {
                                        println!("  <- From {}:", sender);
                                        println!(
                                            "     Encrypted RND: {}...",
                                            &rnd[..15.min(rnd.len())]
                                        );
                                        println!(
                                            "     Signature     : {}...",
                                            &sig[..15.min(sig.len())]
                                        );
                                    }

                                    let msg = MessageToClient::RndMap {
                                        rndnos: inner_map.clone(),
                                    };
                                    let serialized =
                                        format!("{}\n", serde_json::to_string(&msg).unwrap());

                                    if let Err(e) = stream.write_all(serialized.as_bytes()) {
                                        eprintln!("[ERROR] Failed to send RndMap: {}", e);
                                    } else {
                                        println!("[INFO] Sent RndMap to client '{}'.", uname);
                                    }
                                } else {
                                    println!("[WARN] No random numbers stored for '{}'.", uname);
                                }
                            }

                            Ok(MessageToServer::PlainText { text }) => {
                                let user_name = authenticated_username.clone().unwrap_or_default();

                                println!("{}: {}", user_name, text);

                                clients_lock.retain(|s| !s.peer_addr().is_err());

                                for client in clients_lock.iter_mut() {
                                    if client.peer_addr().ok() != reader.get_ref().peer_addr().ok()
                                    {
                                        let x = MessageToClient::PlainTextMessage {
                                            user_name: user_name.clone(),
                                            text: text.clone(),
                                        };
                                        let serialized =
                                            format!("{}\n", serde_json::to_string(&x).unwrap());
                                        if let Err(e) = client.write_all(serialized.as_bytes()) {
                                            eprintln!("Failed to send message: {}", e);
                                        }
                                    }
                                }
                            }
                            Ok(MessageToServer::EncryptedMessage {username,message}) => {
                                

                                println!("{}: {}", username, message);

                                clients_lock.retain(|s| !s.peer_addr().is_err());

                                for client in clients_lock.iter_mut() {
                                    if client.peer_addr().ok() != reader.get_ref().peer_addr().ok()
                                    {
                                        let x = MessageToClient::EncryptedMessage {
                                            username: username.clone(),
                                            message: message.clone(),
                                        };
                                        let serialized =
                                            format!("{}\n", serde_json::to_string(&x).unwrap());
                                        if let Err(e) = client.write_all(serialized.as_bytes()) {
                                            eprintln!("Failed to send message: {}", e);
                                        }
                                    }
                                }
                            }

                            _ => {}

                            Err(e) => {
                                eprintln!("[ERROR] Failed to deserialize message: {}", e);
                                eprintln!("[ERROR] Raw message: {:?}", message);
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

    let mut clients_lock = clients.lock().unwrap();
    if let Some(username) = authenticated_username {
        let mut registry_lock = cert_registry.lock().unwrap();
        if registry_lock.remove(&username).is_some() {
            println!("[INFO] Removed cert entry for user: {}", username);
        }
    }

    clients_lock.retain(|s| !s.peer_addr().is_err());
    println!("[INFO] Client removed.");
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let server_name = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "test_server".to_string());

    create_new_key_private_key(&server_name);
    generate_cert_from_pem(&server_name);

    let listener = TcpListener::bind("127.0.0.1:34254")?;
    println!("-----------------------Server has started----------------------");

    let server_entity = Server::new(server_name.clone());

    let clients = Arc::new(Mutex::new(Vec::new()));
    let client_registry = Arc::new(Mutex::new(HashMap::<String, Client>::new()));

    let rnd_hashmap = Arc::new(Mutex::new(HashMap::<
        String,
        HashMap<String, (String, String)>,
    >::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connecting... {:?}", stream.peer_addr());
                let clients_clone = Arc::clone(&clients);
                let registry_clone = Arc::clone(&client_registry);
                let server_clone = server_entity.clone();
                let client_rnd = Arc::clone(&rnd_hashmap);
                clients.lock().unwrap().push(stream.try_clone().unwrap());

                thread::spawn(move || {
                    handle_client(
                        stream,
                        clients_clone,
                        server_clone,
                        registry_clone,
                        client_rnd,
                    )
                });
            }
            Err(_) => eprintln!("[ERROR] Connection failed"),
        }
    }

    Ok(())
}
