mod parsing;

use clap::Parser;
use log::{debug, info, trace, warn};
use parsing::{Encapsulation, Frame};
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::{DataLink, PcapError, TsResolution};
use std::default;
use std::fs::File;
use std::io::{Write, stdout};
use std::time::SystemTime;
use tokio::net::UdpSocket;

fn encap2datalink(encap: Encapsulation) -> DataLink {
    use DataLink as D;
    use Encapsulation as E;

    match encap {
        E::Ethernet => D::ETHERNET,
        E::Dot11 => D::IEEE802_11,
        E::Ppp => D::PPP,
        E::Fddi => D::FDDI,
        E::Slip => D::SLIP,

        // Not totally sure
        E::TokenRing => D::IEEE802_5,
        E::RawUo => D::RAW,

        e => {
            warn!("Unknown TZSP -> PCAP encapsulation type: {e:?}. Default to ethernet");
            D::ETHERNET
        }
    }
}

struct FrameWriter<W: Write> {
    output: Option<W>,
    writer: Option<PcapWriter<W>>,
    header: PcapHeader,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(output: W) -> Self {
        let mut header = PcapHeader::default();
        header.ts_resolution = TsResolution::NanoSecond;

        Self {
            output: Some(output),
            writer: None,
            header,
        }
    }

    pub fn write(&mut self, frame: &Frame, t: SystemTime) -> Result<(), PcapError> {
        self.init(frame.encapsulation.unwrap_or(Encapsulation::Unknown))?;

        if let Some(encap) = frame.encapsulation {
            let datalink = encap2datalink(encap);
            if (self.header.datalink != datalink) {
                warn!(
                    "Mixed frame encapsulations: {:?}; expected {:?}",
                    datalink, self.header.datalink
                );
            }
        }

        let unix_ts = t
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time after the unix epoch");
        let data = frame.packet_data.unwrap_or(&[]);
        let pkt = PcapPacket::new(unix_ts, frame.orig_len() as u32, data);
        self.writer.as_mut().unwrap().write_packet(&pkt)?;
        Ok(())
    }

    fn init(&mut self, frame_encapsulation: Encapsulation) -> Result<(), PcapError> {
        if self.writer.is_none() {
            let output = self.output.take().unwrap();
            self.header.datalink = encap2datalink(frame_encapsulation);
            self.writer = Some(PcapWriter::with_header(output, self.header)?);
        }
        Ok(())
    }
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

    let out: Box<dyn Write> = if args.output == "-" {
        debug!("Writing to stdout");
        Box::new(stdout())
    } else {
        debug!("Opening output file {}", args.output);
        Box::new(File::create(args.output).expect("Failed to open output"))
    };
    let mut writer = FrameWriter::new(out);

    let ctrlc = tokio::signal::ctrl_c();
    tokio::pin!(ctrlc);

    loop {
        tokio::select! {
            biased;

            recv_res = socket.recv_from(&mut recv_buf) => match recv_res {
                Ok((n, remote_addr)) => {
                    trace!("Got packet from {} of {} bytes", remote_addr, n);
                    match Frame::from_bytes(&recv_buf[0..n]) {
                        Err(e) => warn!("Failed to parse packet: {e}"),
                        Ok(frame) => writer.write(&frame, SystemTime::now()).expect("Failed to write"),
                    }
                }
                Err(e) => warn!("Error waiting for packet: {}", e.kind()),
            },

            ctrlc_res = &mut ctrlc => {
                ctrlc_res.expect("Failed to wait for ctrl-c");
                info!("Received ctrl-c. Quitting");
                break;
            }
        }
    }
}
