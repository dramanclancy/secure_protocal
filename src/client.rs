use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::{env, thread};
use base64::{engine::general_purpose::STANDARD, Engine};
use client_server_functions::client_function::Client;
mod client_server_functions;
use client_server_functions::decryption_module::private_key_decrypt;
use client_server_functions::encryption_module::{encrypt_with_cert, private_key_encrypt};
use client_server_functions::session_key_functions::{generate_random_256, ServerKeyFormulation, SessionKeySetup, };
use client_server_functions::utilities_functions::{compare_maps, create_new_key_private_key, filter_out_by_key, generate_cert_from_pem, sign_message, verify_signature, ClientMessage};
use serde_json;
use std::io::BufReader;
use std::io::BufRead;

fn main() -> std::io::Result<()> {
    
    

    let args:Vec<String> =env::args().collect();

    //Getting username
    let username =args.get(1).cloned().unwrap_or_else(|| "clancy".to_string());


    let server_name="test_server";
    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
    create_new_key_private_key(&username);
    generate_cert_from_pem(&username);
     
    println!("Connected to server. Type messages to send.");
    
    /*Client is set up with given methods to perform fucntionson dat */
    let client_entity=Client::new(username.clone(), "test_server".to_string());
    let (cipher_text,hash_signature,hash)=client_entity.authentication_data("clancy".to_string());
    
    //Cipher text and signed hash put together to send to server
    let auth_data=format!("{}||{}||{}\n",cipher_text,hash_signature,hash);
    println!("Hash: {}",hash);
    

    let mut stream_clone = stream.try_clone()?;

    //send authendication data to server
    #[allow(unused)]
    stream.write_all(auth_data.as_bytes());

    // Thread for receiving messages
    let stream_clone = stream.try_clone()?; // keep this
    let thread_out = Arc::new(Mutex::new(None));
    let thread_out_clone = Arc::clone(&thread_out);
    
thread::spawn(move || {
    let rndx=generate_random_256();
    let mut old_registry = HashMap::new();
    let mut reader = BufReader::new(stream_clone);
    loop {
        let mut message_line = String::new();
        match reader.read_line(&mut message_line) {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let trimmed = message_line.trim_end();
                // println!("\nRaw message: {}", trimmed);

                match serde_json::from_str::<ClientMessage>(trimmed) {
                    Ok(ClientMessage::ClientList { clients_online })=>{
                        old_registry=clients_online;
                        for key in old_registry.keys() {
                            println!("New key added: {:?}", key);
                        }
                        
                    }
                    Ok(ClientMessage::KeyExchange { user_data }) => {
                        println!(
                            " {} Jonied sever.\n ----------Press enter to iniate session key setup----------",
                            user_data.user_name
                        );
                        old_registry=user_data.clients_online;
                        let filtered = filter_out_by_key(&old_registry, &username);
                        let mut already_sent_to = HashSet::new();
                        for port in filtered.values(){
                            if already_sent_to.contains(port) {
                                continue;
                            }
                            already_sent_to.insert(port.clone());
                            let encoded_rndx = STANDARD.encode(rndx);
                            println!("Plain rand: {}",encoded_rndx);
                            let encrypted_random_number =encrypt_with_cert(&user_data.certificate, encoded_rndx.as_str()).unwrap();
                            let signed_random_no=sign_message(&encoded_rndx, &username);

                            let session_message= ServerKeyFormulation{
                                encrypted_random_number,
                                signed_random_number:signed_random_no,
                                port:port.to_string(),
                                user_name:username.clone()
                            };

                            let x=SessionKeySetup::ServerKeyFormulation((session_message));
                            let serialized= format!("{}\n", serde_json::to_string(&x).unwrap());
                            let mut output = thread_out_clone.lock().unwrap();
                            *output = Some(serialized);
                        }
                        
                       
                        
                        
                       

                        //get random number and send it to server 
                        // encerpyt the random number with cert 
                        //sign the random number
                        //send it back to the new guy who has joined
                        //stream.writeall()

                        //store the cert here

                        // get the list of old guys and do the same with stored certs

                       
                        
                    }Ok(ClientMessage::RandomMessage { ClientKeyFormulation })=>{
                        println!("WE ARE IN BUSINESS");
                        println!("{}",ClientKeyFormulation.encrypted_random_number);
                        println!("{}",ClientKeyFormulation.signed_random_number);
                        println!("{}",ClientKeyFormulation.user_name);
                        let random_number_signutre=ClientKeyFormulation.signed_random_number;
                        let other_client= ClientKeyFormulation.user_name;
                        let encrypted_random_number=ClientKeyFormulation.encrypted_random_number;
                        let decrpyted_random_number =private_key_decrypt(encrypted_random_number,username.clone());
                        println!("errorooooor after");
                        println!("Decrypted:{}",decrpyted_random_number);
                        let verification_s=verify_signature(&decrpyted_random_number, &random_number_signutre, &other_client);
                        
                        println!("Session Verified:{}",verification_s);
                                    
                    }
                    Ok(ClientMessage::TextMessage { user_name, text }) => {
                        println!("{}: {}", user_name, text);
                    }
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

use std::time::Duration;
use std::thread::sleep;

loop {
    // ✅ 1. Always check if thread sent something
    if let Some(to_send) = thread_out.lock().unwrap().take() {
        stream.write_all(to_send.as_bytes())?;
    }

    // ✅ 2. Non-blocking check for user input
    let mut input = String::new();
    if let Ok(n) = io::stdin().read_line(&mut input) {
        if n > 0 && input.trim() != "" {
            stream.write_all(input.as_bytes())?;
        }
    }

    // ✅ 3. Avoid spinning too fast
    sleep(Duration::from_millis(100));
}


    Ok(())
}
