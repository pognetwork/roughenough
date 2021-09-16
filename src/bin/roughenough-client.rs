// Copyright 2017-2021 int08h LLC

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

// for value_t_or_exit!()
use std::fs::File;
use std::io::Write;
use std::iter::Iterator;
use std::net::{ToSocketAddrs, UdpSocket};

use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use chrono::offset::Utc;
use chrono::{Local, TimeZone};
use clap::{value_t_or_exit, App, Arg};
use roughenough::client::{
    create_nonce, make_request, receive_response, stress_test_forever, ParsedResponse,
    ResponseHandler,
};
use roughenough::{roughenough_version, Tag};

fn main() {
    let matches = App::new("roughenough client")
    .version(roughenough_version().as_ref())
    .arg(Arg::with_name("host")
      .required(true)
      .help("The Roughtime server to connect to.")
      .takes_value(true))
    .arg(Arg::with_name("port")
      .required(true)
      .help("The Roughtime server port to connect to.")
      .takes_value(true))
    .arg(Arg::with_name("verbose")
      .short("v")
      .long("verbose")
      .help("Output additional details about the server's response."))
    .arg(Arg::with_name("json")
      .short("j")
      .long("json")
      .help("Output the server's response in JSON format."))
    .arg(Arg::with_name("public-key")
      .short("p")
      .long("public-key")
      .takes_value(true)
      .help("The server public key used to validate responses. If unset, no validation will be performed."))
    .arg(Arg::with_name("time-format")
      .short("f")
      .long("time-format")
      .takes_value(true)
      .help("The strftime format string used to print the time recieved from the server.")
      .default_value("%b %d %Y %H:%M:%S %Z")
    )
    .arg(Arg::with_name("num-requests")
      .short("n")
      .long("num-requests")
      .takes_value(true)
      .help("The number of requests to make to the server (each from a different source port). This is mainly useful for testing batch response handling.")
      .default_value("1")
    )
    .arg(Arg::with_name("stress")
      .short("s")
      .long("stress")
      .help("Stress test the server by sending the same request as fast as possible. Please only use this on your own server.")
    )
    .arg(Arg::with_name("output")
      .short("o")
      .long("output")
      .takes_value(true)
      .help("Writes all requests to the specified file, in addition to sending them to the server. Useful for generating fuzzer inputs.")
    )
    .arg(Arg::with_name("zulu")
      .short("z")
      .long("zulu")
      .help("Display time in UTC (default is local time zone)")
    )
    .get_matches();

    let host = matches.value_of("host").unwrap();
    let port = value_t_or_exit!(matches.value_of("port"), u16);
    let verbose = matches.is_present("verbose");
    let json = matches.is_present("json");
    let num_requests = value_t_or_exit!(matches.value_of("num-requests"), u16) as usize;
    let time_format = matches.value_of("time-format").unwrap();
    let stress = matches.is_present("stress");
    let pub_key = matches
        .value_of("public-key")
        .map(|pkey| hex::decode(pkey).expect("Error parsing public key!"));
    let out = matches.value_of("output");
    let use_utc = matches.is_present("zulu");

    if verbose {
        eprintln!("Requesting time from: {:?}:{:?}", host, port);
    }

    let addr = (host, port).to_socket_addrs().unwrap().next().unwrap();

    if stress {
        stress_test_forever(&addr)
    }

    let mut requests = Vec::with_capacity(num_requests);
    let mut file = out.map(|o| File::create(o).expect("Failed to create file!"));

    for _ in 0..num_requests {
        let nonce = create_nonce();
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Couldn't open UDP socket");
        let request = make_request(&nonce);

        if let Some(f) = file.as_mut() {
            f.write_all(&request).expect("Failed to write to file!")
        }

        requests.push((nonce, request, socket));
    }

    for &mut (_, ref request, ref mut socket) in &mut requests {
        socket.send_to(request, addr).unwrap();
    }

    for (nonce, _, mut socket) in requests {
        let resp = receive_response(&mut socket);

        let ParsedResponse {
            verified,
            midpoint,
            radius,
        } = ResponseHandler::new(pub_key.clone(), resp.clone(), nonce).extract_time();

        let map = resp.into_hash_map();
        let index = map[&Tag::INDX]
            .as_slice()
            .read_u32::<LittleEndian>()
            .unwrap();

        let seconds = midpoint / 10_u64.pow(6);
        let nsecs = (midpoint - (seconds * 10_u64.pow(6))) * 10_u64.pow(3);
        let verify_str = if verified { "Yes" } else { "No" };

        let out = if use_utc {
            let ts = Utc.timestamp(seconds as i64, nsecs as u32);
            ts.format(time_format).to_string()
        } else {
            let ts = Local.timestamp(seconds as i64, nsecs as u32);
            ts.format(time_format).to_string()
        };

        if verbose {
            eprintln!(
                "Received time from server: midpoint={:?}, radius={:?}, verified={} (merkle_index={})",
                out, radius, verify_str, index
            );
        }

        if json {
            println!(
                r#"{{ "midpoint": {:?}, "radius": {:?}, "verified": {}, "merkle_index": {} }}"#,
                out, radius, verified, index
            );
        } else {
            println!("{}", out);
        }
    }
}
