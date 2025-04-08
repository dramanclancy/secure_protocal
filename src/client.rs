use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::{env, thread};

use client_server_functions::client_function::Client;
mod client_server_functions;

fn main() -> std::io::Result<()> {
    

    let args:Vec<String> =env::args().collect();
    let username =args.get(1).cloned().unwrap_or_else(|| "clancy".to_string());

    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
     
    println!("Connected to server. Type messages to send.");
    use client_server_functions::client_function;

    let client_entity=Client::new(username.clone(), "test_server".to_string());
    let (cipher_text,signed_hash)=client_entity.authentication_data("clancy".to_string());
    //stream.write_all(buf)

    let auth_data=format!("{}||{}",cipher_text,signed_hash);
    println!("Client Cipher: {}",cipher_text);
    println!("Client Hash: {}",signed_hash);

    let mut stream_clone = stream.try_clone()?;
    stream.write_all(auth_data.as_bytes());

    // Thread for receiving messages
    thread::spawn(move || {
        let mut buffer = [0; 512];
        while let Ok(n) = stream_clone.read(&mut buffer) {
            if n == 0 {
                break;
            }
            let message = String::from_utf8_lossy(&buffer[..n]);
            
            println!("\n{}", message);
        }
    });

    // Main thread for sending messages
    let mut input = String::new();
    while io::stdin().read_line(&mut input)? > 0 {
        if input!="\n" {
            let mut _result=String::from(&input);
            input=username.clone()+": "+&mut input;
            stream.write_all(input.as_bytes())?;
            input.clear();
        }else{
            input.clear();
        }
        
    }

    Ok(())
}
