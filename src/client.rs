use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::{env, thread};
use base64::{engine::general_purpose::STANDARD, Engine};
use client_server_functions::client_function::Client;
mod client_server_functions;
use client_server_functions::session_key_functions::{generate_random_256, ServerKeyFormulation, SessionKeySetup, };
use client_server_functions::utilities_functions::{compare_maps, filter_out_by_key, verify_signature, ClientMessage};
use serde_json;
use std::io::BufReader;
use std::io::BufRead;

fn main() -> std::io::Result<()> {
    
    

    let args:Vec<String> =env::args().collect();

    //Getting username
    let username =args.get(1).cloned().unwrap_or_else(|| "clancy".to_string());
    let server_name="test_server";
    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
     
    println!("Connected to server. Type messages to send.");
    
    /*Client is set up with given methods to perform fucntionson dat */
    let client_entity=Client::new(username.clone(), "test_server".to_string());
    let (cipher_text,signed_hash)=client_entity.authentication_data("clancy".to_string());
    
    //Cipher text and signed hash put together to send to server
    let auth_data=format!("{}||{}\n",cipher_text,signed_hash);
    

    let mut stream_clone = stream.try_clone()?;

    //send authendication data to server
    #[allow(unused)]
    stream.write_all(auth_data.as_bytes());

    // Thread for receiving messages
    let stream_clone = stream.try_clone()?; // keep this
    let thread_out = Arc::new(Mutex::new(None));
    let thread_out_clone = Arc::clone(&thread_out);
    
thread::spawn(move || {
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
                            "Received Key Exchange message from {}.\nCertificate:\n{}",
                            user_data.user_name, user_data.certificate
                        );
                        
                        let filtered = filter_out_by_key(&old_registry, &username);
                        let rndx=generate_random_256();
                        let encoded_rndx = STANDARD.encode(rndx);
                        
                        let sessionMessage= ServerKeyFormulation{
                            encrypted_random_number:encoded_rndx,
                            signed_random_number:"Signature field".to_owned(),
                            port:"Port feild".to_owned()
                        };
                        
                        let x=SessionKeySetup::ServerKeyFormulation((sessionMessage));
                        let serialized= format!("{}\n", serde_json::to_string(&x).unwrap());
                        println!("serialized:{}",serialized);
                        // store it in thread_out_clone
                        let mut output = thread_out_clone.lock().unwrap();
                        *output = Some(serialized);
                        
                        
                       

                        //get random number and send it to server 
                        // encerpyt the random number with cert 
                        //sign the random number
                        //send it back to the new guy who has joined
                        //stream.writeall()

                        //store the cert here

                        // get the list of old guys and do the same with stored certs

                       
                        
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
        println!("[Main] Sending async output: {}", to_send);
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
