use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::{env, thread};
mod cert_mod;


fn main() -> std::io::Result<()> {

    let args:Vec<String> =env::args().collect();
    let username =args.get(1).cloned().unwrap_or_else(|| "Anonymous".to_string());

    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
    
    let ip_addresses =vec!["127.0.0.1".to_string()];

    //cert creation and update
    let certified_key =cert_mod::cert::cert_creation(ip_addresses);
    let cert_file_name = format!("src/auth_cert/{}_cert.pem", username);
let key_file_name = format!("src/auth_cert/{}_key.pem", username);




    cert_mod::cert::write_to_file(
    &key_file_name, 
    &certified_key.key_pair.serialize_pem(), 
    &cert_file_name, 
    &certified_key.cert.pem()
    );

   

    println!("Connected to server. Type messages to send.");

    let mut stream_clone = stream.try_clone()?;

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
            input=username.clone()+": "+&mut input;
            stream.write_all(input.as_bytes())?;
            input.clear();
        }else{
            input.clear();
        }
        
    }

    Ok(())
}
