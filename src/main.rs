mod cli;
mod protocols;
use crate::protocols::udp::*;
use crate::protocols::ipv4::*;
use crate::protocols::tcp::*;
use pktparse::ethernet::{parse_vlan_ethernet_frame, EtherType};
use crate::cli::arguments;
use pcap::Capture;
use std::time::Instant;

// to-do 
// not working on wsl
pub fn online_capture(device_name : &str) {
    let mut cap = Capture::from_device(device_name).unwrap().promisc(true).snaplen(5000).open().unwrap();
    
    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
    }
}

pub fn offline_capture(file_path: &str) {

    let mut cap = Capture::from_file(file_path).unwrap();

    while let Ok(packet) = cap.next_packet() {
        //let packet_length = packet.header.len;
        //let packet_capture_time = packet.header.ts;
        let packet_data = packet.data;
        println!();
        if let Ok((payload, frame)) = parse_vlan_ethernet_frame(packet_data) {
            match frame.ethertype {
                EtherType::IPv4 => {
                    if let Ok((payload, ipv4data)) = parse_ipv4(payload) {
                        println!("{:?}",ipv4data);
                        match ipv4data.protocol_type {
                            IpType::TCP => {
                                println!("TCP");
                                match parse_tcp(payload) {
                                    Ok(tcp_data) => {
                                        println!("{:?}", tcp_data); 
                                        if tcp_data.tcp_header.dest_port == 80 || tcp_data.tcp_header.source_port == 80 {
                                            println!("HTTP message.");
                                        } else if tcp_data.tcp_header.dest_port == 443 || tcp_data.tcp_header.source_port == 443 {
                                            println!("HTTPS message.");
                                        } else if tcp_data.tcp_header.dest_port == 22 || tcp_data.tcp_header.source_port == 22 {
                                            println!("SSH message.");
                                        }
                                    }
                                    Err(e) => println!("{:?}",e),
                                }
                            }
                            IpType::UDP => {
                                if let Ok((_payload, udp_data)) = parse_udp(payload) {
                                    println!("{:?}", udp_data);
                                    if udp_data.src_port == 443 || udp_data.dst_port == 443 {
                                        println!("QUIC");
                                    }
                                }
                                else {
                                    println!("Error parsing UDP");
                                }
                            }
                            IpType::ICMP => {
                                println!("ICMP");
                            }
                            _ => { println!("L4 protocol not supported.")}
                        }
                    }
                }
                EtherType::IPv6 => {
                    if let Ok((_payload, header)) = pktparse::ipv6::parse_ipv6_header(payload) {
                        println!("{:?}", header);
                    }   
                    else {
                        println!("error parsing ipv6");
                    }
                }
                _ => println!("Not supported ether type"),
            }
        }
        else {
            println!("Error parsing ethernet layer");
        } 
    }
}

fn main() {
    let before = Instant::now();
    let opts = arguments().run();
    println!("{} {}", opts.capture_type, opts.input);

    offline_capture(&opts.input);

    println!("Elapsed time : {:.2?}", before.elapsed());
}