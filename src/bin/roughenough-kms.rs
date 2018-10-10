// Copyright 2017-2018 int08h LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//!
//! Work with Roughenough long-term key
//!

extern crate clap;
#[macro_use]
extern crate log;
extern crate hex;
extern crate ring;
extern crate roughenough;
extern crate simple_logger;
extern crate untrusted;

use clap::{App, Arg};
use roughenough::VERSION;
use roughenough::key::EnvelopeEncryption;

#[cfg(feature = "kms")]
use roughenough::key::awskms::AwsKms;

#[cfg(feature = "kms")]
fn aws_kms(kms_key: &str, plaintext_seed: &[u8]) {
    let client = AwsKms::from_arn(kms_key).unwrap();

    match EnvelopeEncryption::encrypt_seed(&client, &plaintext_seed) {
        Ok(encrypted_blob) => {
            println!("key_protection: \"{}\"", kms_key);
            println!("seed: {}", hex::encode(&encrypted_blob));
        }
        Err(e) => {
            error!("Error: {:?}", e);
        }
    }
}

pub fn main() {
    use log::Level;

    simple_logger::init_with_level(Level::Info).unwrap();

    let matches = App::new("Roughenough key management")
        .version(VERSION)
        .arg(Arg::with_name("kms-key")
            .short("k")
            .long("kms-key")
            .takes_value(true)
            .required(true)
            .help("Identity of the KMS key to be used"))
        .arg(Arg::with_name("seed")
            .short("s")
            .long("seed")
            .takes_value(true)
            .required(true)
            .help("Seed for the server's long-term identity"))
        .get_matches();

    let kms_key = matches.value_of("kms-key").unwrap();
    let plaintext_seed = matches.value_of("seed")
        .map(|seed| hex::decode(seed).expect("Error parsing seed value"))
        .unwrap();

    if plaintext_seed.len() != 32 {
        error!("Seed must be 32 bytes long; provided seed is {}", plaintext_seed.len());
        return;
    }

    if cfg!(feature = "kms") {
        #[cfg(feature = "kms")]
        aws_kms(kms_key, &plaintext_seed);
    } else {
        warn!("KMS not enabled, nothing to do");
    }
}
