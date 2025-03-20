// use chrono::{DateTime, Utc};
// use std::{fs::File, io::BufReader, time::SystemTime};
// use rand::Rng;
// use sha256::digest;
// use std::io::{self, BufRead};
// use openssl::rsa::{Padding, Rsa};
// use openssl::pkey::Private;
// use openssl::error::ErrorStack;

// struct my_data{
//     data:String,
//     hash:String
// }

// pub fn auth_encupsulation(personal_cert:String,username:String )
// ->Result<my_data,String>
// {
// //get current time;
// //Ta
// let T=SystemTime::now();
// let datetime: DateTime<Utc> = T.into();
// let formatted_time = datetime.to_rfc3339();

// //create random Nonce;
// //Na
// let mut rng = rand::thread_rng();
// let random_number: u32 = rng.gen_range(1..=1_000_000_000);


// /*Concatinet data------>data=Ta||Na||IDa*/
// let data=format!("{}||{}||{}",formatted_time,random_number,username);



// //Encrpyt for server



// //hash data
// let hash=digest(&data);
// //Sign hashed data

// //return encrpted and hashed for success
//     return Ok(my_data{data:data,hash:hash});
// }

// pub fn auth_approval(data:my_data)
// {
//     //decrypt data and get ID



//     //check time and nonce
//     let mut extraction=my_data.data;
//     let data=extraction.data;

//     //verify hash using id

//     //return ok()
//     return;
// }


