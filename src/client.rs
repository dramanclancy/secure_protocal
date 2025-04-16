// Import required modules
use aes_gcm::aead::{rand_core::RngCore, Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or Aes128Gcm if 128-bit key
use base64::{engine::general_purpose::STANDARD, Engine};
use client_server_functions::client_function::Client;
use client_server_functions::decryption_module::private_key_decrypt;
use once_cell::sync::Lazy;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::{env, thread};

mod client_server_functions;
use client_server_functions::encryption_module::encrypt_with_cert;
use client_server_functions::session_key_functions::generate_random_256;
use client_server_functions::utilities_functions::{
    create_new_key_private_key, generate_cert_from_pem, hash_and_encode, sign_message,
    verify_signature, MessageToClient, MessageToServer,
};
use serde_json;
use std::io::{BufRead, BufReader};
static SESSION_KEY: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

pub fn encrypt_message(session_key_base64: &str, plaintext: &str) -> Option<String> {
    let key_bytes = STANDARD.decode(session_key_base64).ok()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).ok()?;

    let nonce_b64 = STANDARD.encode(nonce_bytes);
    let cipher_b64 = STANDARD.encode(ciphertext);

    Some(format!("{}:{}", nonce_b64, cipher_b64))
}

pub fn decrypt_message(session_key_base64: &str, encrypted: &str) -> Option<String> {
    let parts: Vec<&str> = encrypted.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }

    let nonce_bytes = STANDARD.decode(parts[0]).ok()?;
    let cipher_bytes = STANDARD.decode(parts[1]).ok()?;

    let key_bytes = STANDARD.decode(session_key_base64).ok()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, cipher_bytes.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let username = args.get(1).cloned().unwrap_or_else(|| "clancy".to_string());

    // Connect to the chat server
    let mut stream = TcpStream::connect("127.0.0.1:34254")?;
    let server_name = "test_server";

    // Generate keys and certificate
    create_new_key_private_key(&username);
    generate_cert_from_pem(&username);
    println!("✅ Connected to server as '{}'", username);

    // Authentication data creation
    let client_entity = Client::new(username.clone(), server_name.to_string());
    let (cipher_text, hash_signature, hash) = client_entity.authentication_data(username.clone());
    let auth_data = format!("{}||{}||{}\n", cipher_text, hash_signature, hash);
    println!("🔐 Authentication Hash: {}", hash);

    // Send authentication data
    stream.write_all(auth_data.as_bytes())?;

    // Shared map for online certificates
    let online_cert = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let cert_map_clone = Arc::clone(&online_cert);

    // Constant random number for the session
    let rndx = generate_random_256();

    // Storage for verified RNDs received from others
    let verified_rndnos: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let verified_rndnos_clone = Arc::clone(&verified_rndnos);

    let username_clone = username.clone();
    let stream_clone = stream.try_clone()?;

    // 🔁 Receiver thread
    thread::spawn(move || {
        let mut reader = BufReader::new(stream_clone);
        loop {
            let mut message_line = String::new();
            match reader.read_line(&mut message_line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = message_line.trim_end();

                    match serde_json::from_str::<MessageToClient>(trimmed) {
                        Ok(MessageToClient::ClientList { clients_online }) => {
                            println!("📶 Online users: {:?}", clients_online);
                        }
                        Ok(MessageToClient::PlainTextMessage { user_name, text }) => {
                            println!("🔓💬{}: {}", user_name, text);
                        }
                        Ok(MessageToClient::CertHashMap { cert }) => {
                            if cert.is_empty() {
                                println!("⚠️ No certificates received.");
                            } else {
                                println!("📜 ---- Received Certificates ----");
                                let mut map = cert_map_clone.lock().unwrap();
                                for (user, pem_cert) in cert {
                                    println!("👤 User: {}\n📄 Cert:\n{}\n", user, pem_cert);
                                    map.insert(user.clone(), pem_cert);
                                }
                                println!("--------------------------------");
                            }
                        }
                        Ok(MessageToClient::EncryptedMessage { username, message }) => {
                            let session_key_guard = SESSION_KEY.lock().unwrap();

                            if let Some(key) = session_key_guard.as_ref() {
                                let m = decrypt_message(key, &message).unwrap();
                                println!("🔐💬 {}: {}", username, m);
                            } else {
                                eprintln!(
                                    "⚠️ No session key available. Cannot decrypt message from {}",
                                    username
                                );
                            }
                        }

                        Ok(MessageToClient::RndMap { rndnos }) => {
                            println!("🔑 [INFO] Received Random Numbers for Session Key:");

                            let mut verified = verified_rndnos_clone.lock().unwrap();
                            verified.clear();

                            for (sender, (rnd, sig)) in rndnos.iter() {
                                println!("📥 From: {}", sender);
                                println!("    🔐 Encrypted RND: {}...", &rnd[..15.min(rnd.len())]);
                                println!("    ✍️ Signature     : {}...", &sig[..15.min(sig.len())]);

                                println!("------------------------------------------");
                                println!("🔓 Encrypted RND (raw): {}", rnd);
                                let rnd_decrypted =
                                    private_key_decrypt(rnd.clone(), username_clone.clone());
                                println!("🔓 Decrypted RND: {}", rnd_decrypted);
                                println!("------------------------------------------");

                                let hash = hash_and_encode(rnd_decrypted.clone());
                                let valid = verify_signature(&hash, &sig, &username_clone);

                                if valid {
                                    println!("✅ Signature verified.");
                                    verified.push((sender.clone(), rnd_decrypted));

                                    if !verified.is_empty() {
                                        let mut all_rnds: Vec<(String, String)> = verified.clone();

                                        // Add own (username, base64-encoded rndx)
                                        let self_b64 = STANDARD.encode(&rndx);
                                        all_rnds.push((username_clone.clone(), self_b64));

                                        // Sort all entries by sender name
                                        all_rnds.sort_by(|a, b| a.0.cmp(&b.0));

                                        // Combine decoded bytes
                                        let mut combined = Vec::new();
                                        for (_, b64_rnd) in all_rnds.iter() {
                                            let decoded = STANDARD
                                                .decode(b64_rnd)
                                                .expect("Failed to decode RND");
                                            combined.extend_from_slice(&decoded);
                                        }

                                        // Derive session key
                                        let session_key = Sha256::digest(&combined);
                                        let session_key_string = STANDARD.encode(session_key);

                                        // Save globally
                                        {
                                            let mut global_key = SESSION_KEY.lock().unwrap();
                                            *global_key = Some(session_key_string.clone());
                                        }

                                        println!("🔐 Derived Session Key: {}", session_key_string);
                                    }
                                } else {
                                    println!("❌ Signature verification failed.");
                                }
                            }

                            println!(
                                "[INFO] ✅ Stored {} verified random numbers.",
                                verified.len()
                            );
                            println!("------------------------------------------");
                        }
                        _ => {}
                        Err(e) => {
                            eprintln!("❌ Failed to deserialize message: {}", e);
                            eprintln!("Raw line: {:?}", trimmed);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Error reading from stream: {}", e);
                    break;
                }
            }
        }
    });

    use std::thread::sleep;
    use std::time::Duration;
    let mut input = String::new();

    // 🧠 Main input loop
    while io::stdin().read_line(&mut input)? > 0 {
        let trimmed = input.trim();
        if !trimmed.is_empty() {
            let mut handled = false;

            if trimmed.len() == 2 {
                match trimmed {
                    "-s" => {
                        println!("📡 Requesting certificates...");
                        let x = MessageToServer::GetCerts {
                            user_name: username.clone(),
                        };
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                    }
                    "-l" => {
                        println!("📡 Requesting list of online users...");
                        let x = MessageToServer::GetUserOnline {};
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                    }
                    "-o" => {
                        let rnd_no_encoded = STANDARD.encode(&rndx);
                        println!("🔐 Using constant random number: {}", rnd_no_encoded);

                        let map = online_cert.lock().unwrap();
                        for (username, cert) in map.iter() {
                            println!("🔒 Encrypting RND for {}", username);
                            let encrypted_rnd_no =
                                encrypt_with_cert(cert, &rnd_no_encoded).unwrap();
                            let rnd_hash = hash_and_encode(rnd_no_encoded.clone());
                            let rnd_no_signature = sign_message(&rnd_hash, &username);

                            let x = MessageToServer::SendRndNos {
                                encrypted_rnd_no,
                                rnd_no_signature,
                                forclient: username.clone(),
                            };

                            let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                            stream.write_all(serialized.as_bytes())?;
                        }

                        handled = true;
                    }
                    "-k" => {
                        println!("🔑 Requesting session key establishment...");
                        let x = MessageToServer::CreateNewSsessionKeys {
                            uname: username.clone(),
                        };
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                    }
                    _ => println!("❓ Unknown command."),
                }
            } else if trimmed.starts_with("-en") {
                let to_encrypt = trimmed.strip_prefix("-en").unwrap().trim();
                if to_encrypt.is_empty() {
                    eprintln!(
                        "⚠️ No message provided after '-en'. Please enter a message to encrypt."
                    );
                } else {
                    let session_key_guard = SESSION_KEY.lock().unwrap();

                    if let Some(key) = session_key_guard.as_ref() {
                        let m = encrypt_message(key, &to_encrypt).unwrap();
                        let x = MessageToServer::EncryptedMessage { 
                            username:username.clone(), 
                            message:m.clone()} ;
                        let serialized = format!("{}\n", serde_json::to_string(&x).unwrap());
                        stream.write_all(serialized.as_bytes())?;
                        handled = true;
                        println!("🔐💬 {}: {}", username, m);
                    } else {
                        eprintln!(
                            "⚠️ No session key available. Cannot decrypt message from {}",
                            username
                        );
                    }
                }
            }

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

        input.clear();
        sleep(Duration::from_millis(100));
    }

    Ok(())
}
