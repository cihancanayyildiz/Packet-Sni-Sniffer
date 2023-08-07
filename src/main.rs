mod cli;
mod protocols;
use crate::protocols::udp::*;
use crate::protocols::ipv4::*;
use crate::protocols::ethernet::*;
use crate::protocols::tcp::*;
use crate::cli::arguments;
use pcap::Capture;

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
        let packet_length = packet.header.len;
        let packet_capture_time = packet.header.ts;
        let packet_data = packet.data;
        println!();
        if let Ok((payload, frame)) = protocols::ethernet::parse_ethernet_layer(packet_data) {
            println!("{:x?}", frame);
            match frame.ether_type {
                EthernetType::Ipv4 => {
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

                                /* if let Ok(tcp_data) = parse_tcp(payload){
                                    println!("{:?}", tcp_data); 
                                    if tcp_data.tcp_header.dest_port == 80 || tcp_data.tcp_header.source_port == 80 {
                                        println!("HTTP message.");
                                    } else if tcp_data.tcp_header.dest_port == 443 || tcp_data.tcp_header.source_port == 443 {
                                        println!("HTTPS message.");
                                    } else if tcp_data.tcp_header.dest_port == 22 || tcp_data.tcp_header.source_port == 22 {
                                        println!("SSH message.");
                                    }
                                }
                                else {
                                    println!("Error parsing TCP");
                                } */
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
                    else {
                        println!("ipv4 parsing error.");
                    }
                }
                _ => { println!("L3 protocol not supported.")}
            }
        }

    }
}

fn main() {
    let opts = arguments().run();
    println!("{} {}", opts.capture_type, opts.input);

    offline_capture(&opts.input);
}