use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::{env, thread};

use client_server_functions::client_function::Client;
mod client_server_functions;
use client_server_functions::utilities_functions::ClientMessage;
use serde_json;
use std::io::BufReader;
use std::io::BufRead;

fn main() -> std::io::Result<()> {
    

    let args:Vec<String> =env::args().collect();

    //Getting username
    let username =args.get(1).cloned().unwrap_or_else(|| "clancy".to_string());
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
thread::spawn(move || {
    let mut reader = BufReader::new(stream_clone);
    loop {
        let mut message_line = String::new();
        match reader.read_line(&mut message_line) {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let trimmed = message_line.trim_end();
                println!("\nRaw message: {}", trimmed);

                match serde_json::from_str::<ClientMessage>(trimmed) {
                    Ok(ClientMessage::KeyExchange { user_data }) => {
                        println!(
                            "Received Key Exchange message from {}.\nCertificate:\n{}",
                            user_data.user_name, user_data.certificate
                        );
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

    // Main thread for sending messages
    let mut input = String::new();
    while io::stdin().read_line(&mut input)? > 0 {

        if input!="\n" {
            let mut _result=String::from(&input);
            stream.write_all(input.as_bytes())?;
            input.clear();
        }else{
            input.clear();
        }
        
    }

    Ok(())
}
