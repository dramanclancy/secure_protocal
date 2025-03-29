use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::{env, thread};
mod cert_mod;


fn main() -> std::io::Result<()> {

    let args:Vec<String> =env::args().collect();
    let username =args.get(1).cloned().unwrap_or_else(|| "Anonymous".to_string());

    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
   
    //auth here

    //check for  chat or lse create it

    //if a user joins chat initate key exchange over s 
     
    println!("Connected to server. Type messages to send.");
    use cert_mod::auth::*;


    let user=Entity::new(username.clone());
    let (data,hash)=user.auth_data();
    let auth_c=format!("{}||{}",data,hash);
    stream.write_all(auth_c.as_bytes())?;

    //Entity::auth_data()
    let mut stream_clone = stream.try_clone()?;

    // Thread for receiving messages
    thread::spawn(move || {
        let mut buffer = [0; 512];
        while let Ok(n) = stream_clone.read(&mut buffer) {
            if n == 0 {
                break;
            }
            let message = String::from_utf8_lossy(&buffer[..n]);
            //sesiosn cretion
            //decreaion
            //message printing
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
