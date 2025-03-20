use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::{env, result, thread};



fn main() -> std::io::Result<()> {

    let args:Vec<String> =env::args().collect();
    let username =args.get(1).cloned().unwrap_or_else(|| "Anonymous".to_string());

    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
    

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
            let mut result=String::from(&input);
            input=username.clone()+": "+&mut input;
            stream.write_all(input.as_bytes())?;
            input.clear();
        }else{
            input.clear();
        }
        
    }

    Ok(())
}
