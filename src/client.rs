use base64::{engine::general_purpose::STANDARD, Engine};
use client_server_functions::client_function::Client;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::{env, thread};
mod client_server_functions;
use client_server_functions::encryption_module::{encrypt_with_cert, private_key_encrypt};
use client_server_functions::session_key_functions::generate_random_256;
use client_server_functions::utilities_functions::{
    compare_maps, create_new_key_private_key, filter_out_by_key, generate_cert_from_pem,
    sign_message, verify_signature, MessageToClient, MessageToServer,
};
use serde_json;
use std::io::BufRead;
use std::io::BufReader;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    //Getting username
    let username = args.get(1).cloned().unwrap_or_else(|| "clancy".to_string());

    let server_name = "test_server";
    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
    create_new_key_private_key(&username);
    generate_cert_from_pem(&username);

    println!("Connected to server. Type messages to send.");

    /*Client is set up with given methods to perform fucntionson dat */
    let client_entity = Client::new(username.clone(), "test_server".to_string());
    let (cipher_text, hash_signature, hash) =
        client_entity.authentication_data("clancy".to_string());

    //Cipher text and signed hash put together to send to server
    let auth_data = format!("{}||{}||{}\n", cipher_text, hash_signature, hash);
    println!("Hash: {}", hash);

    let mut stream_clone = stream.try_clone()?;

    //send authendication data to server
    #[allow(unused)]
    stream.write_all(auth_data.as_bytes());

    // Thread for receiving messages
    let stream_clone = stream.try_clone()?; // keep this

    thread::spawn(move || {
        let rndx = generate_random_256();
        let mut reader = BufReader::new(stream_clone);
        loop {
            let mut message_line = String::new();
            match reader.read_line(&mut message_line) {
                Ok(0) => break, // Connection closed
                Ok(_) => {
                    let trimmed = message_line.trim_end();
                    // println!("{}", trimmed);

                    match serde_json::from_str::<MessageToClient>(trimmed) {
                        Ok(MessageToClient::ClientList { clients_online }) => {}
                        Ok(MessageToClient::TextMessage { user_name, text }) => {
                            println!("{}: {}", user_name, text);
                        }
                        Ok(MessageToClient::CertHashMap { cert }) => {
                            if cert.is_empty() {
                                println!("No certificates received.");
                            } else {
                                println!("---- Received Certificates ----");
                                for (user, pem_cert) in cert.iter() {
                                    if !pem_cert.trim().is_empty() {
                                        println!("User: {}\nCert:\n{}\n", user, pem_cert);
                                    } else {
                                        println!("User: {} has no cert.", user);
                                    }
                                }
                                println!("--------------------------------");
                            }
                        }
                        _ => {}
                        Err(e) => {
                            eprintln!("Failed to deserialize message: {}", e);
                            eprintln!("Raw line: {:?}", trimmed);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from stream: {}", e);
                    break;
                }
            }
        }
    });

    use std::thread::sleep;
    use std::time::Duration;

    let mut input = String::new();
    while io::stdin().read_line(&mut input)? > 0 {
        let trimmed = input.trim();
        if !trimmed.is_empty() {
            let mut handled = false;
            if trimmed.len() == 2 {
                match trimmed {
                    "-s" => {
                        let x = MessageToServer::GetCerts {
                            user_name: username.clone(),
                        };
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                    }
                    "-l" => {
                        let x = MessageToServer::GetUserOnline {};
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                    }
                    "-o" => {
                        let x = MessageToServer::SendRndNos {};
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                    }
                    "-k" => {
                        let x = MessageToServer::CreateNewSsessionKeys {};
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                    }
                    _ => println!("Enter valid input"),
                }
            } else if trimmed.starts_with("-en") {
                // handle encryption mode here
                handled = true;
            }

            // Only send plain text if the command wasn’t handled
            if !handled {
                let x = MessageToServer::PlainText {
                    text: trimmed.to_owned(),
                };
                let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                stream.write_all(serialized.as_bytes())?;
            }

            input.clear();
            sleep(Duration::from_millis(100));
        }
        input.clear(); // clear buffer for next line
        sleep(Duration::from_millis(100)); // avoid tight loop
    }

    Ok(())
}
