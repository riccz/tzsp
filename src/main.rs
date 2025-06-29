use clap::Parser;
use libc::timeval;
use log::{debug, info, trace, warn};
use pcap::Capture;
use std::time::SystemTime;
use tokio::net::UdpSocket;

mod tzsp;

use tzsp::Frame;

fn now_as_timeval() -> timeval {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    timeval {
        tv_sec: now.as_secs() as i64,
        tv_usec: now.subsec_micros() as i64,
    }
}

fn write_tzsp(savefile: &mut pcap::Savefile, frame: &Frame) {
    let header = pcap::PacketHeader {
        ts: now_as_timeval(),
        caplen: frame.data_len() as u32,
        len: frame.orig_len() as u32,
    };

    let pkt = pcap::Packet {
        header: &header,
        data: frame.packet_data.unwrap_or([].as_slice()),
    };
    savefile.write(&pkt);
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "-")]
    output: String,

    #[arg(short, long, default_value = "37008")]
    port: u16,

    #[arg(short, long, default_value = "0.0.0.0")]
    listen_address: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    env_logger::init();

    let socket = UdpSocket::bind((args.listen_address, args.port))
        .await
        .expect("Failed to bind");
    let local_addr = socket.local_addr().unwrap();
    info!("TZSP listener bound to {}", local_addr);

    const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;
    let mut recv_buf: Vec<u8> = vec![0; MAX_UDP_PAYLOAD];

    debug!("Opening save file {}", args.output);
    let capture =
        Capture::dead_with_precision(pcap::Linktype::ETHERNET, pcap::Precision::Micro).unwrap();
    let mut savefile = capture.savefile(args.output).unwrap();

    let ctrlc = tokio::signal::ctrl_c();
    tokio::pin!(ctrlc);

    loop {
        tokio::select! {
            biased;
            sok = socket.recv_from(&mut recv_buf) => match sok {
                Ok((n, remote_addr)) => {
                    trace!("Got packet from {} of {} bytes", remote_addr, n);
                    match Frame::from_bytes(&recv_buf[0..n]) {
                        Err(e) => warn!("Failed to parse packet: {e}"),
                        Ok(frame) => {
                            write_tzsp(&mut savefile, &frame);
                        }
                    }
                }
                Err(e) => {
                    warn!("Error waiting for packet: {}", e.kind())
                }
            },


            ctrlc_res = &mut ctrlc =>  {
                ctrlc_res.expect("Failed to wait for ctrl-c");

                    info!("Received ctrl-c. Quitting");
                    break;
            }
        }
    }

    savefile.flush().unwrap();
    debug!("Flushed savefile");
}
