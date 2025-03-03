use std::{fs::OpenOptions, io::Write};

use rcgen::{generate_simple_self_signed, CertifiedKey};
//Generation of the cert

pub fn cert_creation(ip_addressess:Vec<String>)->CertifiedKey{
    generate_simple_self_signed(ip_addressess).unwrap()
}

//create key and cert files
pub fn write_to_file(key_path:&str, key_content:&str,cert_path:&str, cert_content:&str){
    let mut key_file =OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(key_path)
        .unwrap();
    let _ =key_file.write_all(key_content.as_bytes());

    let mut cert_file =OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(cert_path)
        .unwrap();
    let _ =cert_file.write_all(cert_content.as_bytes());



}

