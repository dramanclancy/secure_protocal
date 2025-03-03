use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
mod cert_mod;



fn handle_client(mut stream: TcpStream, clients: Arc<Mutex<Vec<TcpStream>>>) {
    //Stream buffer to store incomming messages
    let mut buffer = [0; 512];

    //case to chea=ck if the buffer has any data
    loop {
        
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("Client disconnected.");
                break;
            }
            //read buffer if there is any data
            Ok(n) => {
                //cert creation or setup
                let message = String::from_utf8_lossy(&buffer[..n]);
                println!("{}", message);

                // Broadcast message to all connected clients
                let mut clients_lock = clients.lock().unwrap();
                clients_lock.retain(|s| !s.peer_addr().is_err()); // Remove disconnected clients

                for client in clients_lock.iter_mut() {
                    if client.peer_addr().ok() != stream.peer_addr().ok() {
                        // Avoid echoing to sender  
                        if let Err(e) = client.write_all(message.as_bytes()) {
                            eprintln!("Failed to send message: {}", e);
                        }
                    }
                }
            }
            Err(_) => {
                println!("Client connection error.");
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
    let listener = TcpListener::bind("127.0.0.1:34254")?;
    println!("Server is running on 127.0.0.1:34254");
    

    let clients = Arc::new(Mutex::new(Vec::new())); // Shared list of clients

    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connected: {:?}", stream.peer_addr());

                let clients_clone = Arc::clone(&clients);
                clients.lock().unwrap().push(stream.try_clone().unwrap());

                thread::spawn(move || handle_client(stream, clients_clone));
            }
            Err(_) => eprintln!("Connection failed"),
        }
    }
    Ok(())
}
