// From <https://web.archive.org/web/20050404125022/http://www.networkchemistry.com/support/appnotes/an001_tzsp.html>

use nom::combinator::{eof, fail};
use nom::{Finish, IResult, Parser, bits, bytes, number};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("TZSP parse error")]
    Parse(nom::error::ErrorKind),
}

fn aligned(input: (&[u8], usize)) -> IResult<(&[u8], usize), ()> {
    if input.1 % 8 == 0 {
        Ok((input, ()))
    } else {
        fail().parse(input)
    }
}

fn version(input: &[u8]) -> IResult<&[u8], ()> {
    bytes::complete::tag([0x01].as_slice())
        .map(|_| ())
        .parse(input)
}

#[derive(Debug, Clone, Copy)]
pub struct Flags {
    pub no_tagged_fields: bool,
    pub no_packet_data: bool,
}

impl Flags {
    fn parse(input: (&[u8], usize)) -> IResult<(&[u8], usize), Self> {
        use bits::complete::bool;

        // 4 bits: the 2 `Flags` members + 2 unused ones
        (bool, bool, bool, bool)
            .map(|(no_tagged_fields, no_packet_data, _, _)| Self {
                no_tagged_fields,
                no_packet_data,
            })
            .parse(input)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Type {
    RxPacket,
    TxPacket,
    Config,
    Null,
    Port,
}

impl Type {
    fn parse(input: (&[u8], usize)) -> IResult<(&[u8], usize), Self> {
        bits::complete::take(4usize)
            .map_opt(|n: u8| match n {
                0 => Some(Type::RxPacket),
                1 => Some(Type::TxPacket),
                3 => Some(Type::Config),
                4 => Some(Type::Null),
                5 => Some(Type::Port),
                _ => None,
            })
            .parse(input)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Command {
    pub flags: Flags,
    pub packet_type: Type,
}

impl Command {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = version(input)?; // Only 1 version is known
        let (input, (flags, packet_type, _)) =
            bits::bits((Flags::parse, Type::parse, aligned))(input)?;
        Ok((input, Self { flags, packet_type }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Encapsulation {
    Unknown,
    Ethernet,
    TokenRing,
    Slip,
    Ppp,
    Fddi,
    RawUo,
    Dot11,
}

impl Encapsulation {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        number::be_u16()
            .map_opt(|n| match n {
                0 => Some(Encapsulation::Unknown),
                1 => Some(Encapsulation::Ethernet),
                2 => Some(Encapsulation::TokenRing),
                3 => Some(Encapsulation::Slip),
                4 => Some(Encapsulation::Ppp),
                5 => Some(Encapsulation::Fddi),
                7 => Some(Encapsulation::RawUo),
                18 => Some(Encapsulation::Dot11),
                _ => None,
            })
            .parse(input)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Dot11PacketCapture,
    Dot11StatisticsAnalysis,
    EthernetPacketCapture,
}

impl Mode {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        number::be_u16()
            .map_opt(|n| match n {
                0 => Some(Mode::Dot11PacketCapture),
                1 => Some(Mode::Dot11StatisticsAnalysis),
                2 => Some(Mode::EthernetPacketCapture),
                _ => None,
            })
            .parse(input)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaggedField<'a> {
    Pad,
    End,

    Other { tag: u8, value: &'a [u8] },
}

impl<'a> TaggedField<'a> {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        use bytes::complete::take;

        let (input, tag) = number::u8().parse(input)?;

        match tag {
            0 => Ok((input, TaggedField::Pad)),
            1 => Ok((input, TaggedField::End)),
            tag => {
                let (input, length) = number::u8().parse(input)?;
                let (input, value) = take(length).parse(input)?;
                Ok((input, TaggedField::Other { tag, value }))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaggedFields<'a> {
    tfs: Vec<TaggedField<'a>>,
}

impl<'a> TaggedFields<'a> {
    fn parse(mut input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let mut tfs = vec![];
        loop {
            let (next, tf) = TaggedField::parse(input)?;
            input = next;
            match tf {
                // Padding and End tags don't have any useful info
                TaggedField::Pad => {}
                TaggedField::End => return Ok((input, Self { tfs })),
                tf => tfs.push(tf),
            }
        }
    }

    pub fn as_slice(&self) -> &[TaggedField<'a>] {
        self.tfs.as_slice()
    }
}

#[derive(Debug, Clone)]
pub struct Frame<'a> {
    pub command: Command,
    pub encapsulation: Option<Encapsulation>,
    pub mode: Option<Mode>,
    pub tagged_fields: Option<TaggedFields<'a>>,
    pub packet_data: Option<&'a [u8]>,
}

impl<'a> Frame<'a> {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (input, command) = Command::parse(input)?;

        let (input, (encapsulation, mode)) = match command.packet_type {
            Type::RxPacket | Type::TxPacket => {
                Encapsulation::parse.map(|e| (Some(e), None)).parse(input)?
            }
            _ => Mode::parse.map(|m| (None, Some(m))).parse(input)?,
        };

        let (input, tagged_fields) = if command.flags.no_tagged_fields {
            (input, None)
        } else {
            TaggedFields::parse.map(Some).parse(input)?
        };

        let (input, packet_data) = if command.flags.no_packet_data {
            (input, None)
        } else {
            nom::combinator::rest.map(Some).parse(input)?
        };

        eof(input)?;

        Ok((
            input,
            Self {
                command,
                encapsulation,
                mode,
                tagged_fields,
                packet_data,
            },
        ))
    }

    pub fn from_bytes(pkt: &'a [u8]) -> Result<Self, Error> {
        let (_, frame) = Self::parse(pkt)
            .finish()
            .map_err(|e| Error::Parse(e.code))?;
        Ok(frame)
    }

    pub fn data_len(&self) -> usize {
        self.packet_data.map_or(0, |d| d.len())
    }

    pub fn orig_len(&self) -> usize {
        // TODO: this could be in TZSP_ORIGINAL_LENGTH (41)
        self.data_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn test_mikrotik_ethernet_header() {
        let payload = hex_bytes("0100000101ffffff");
        let frame = Frame::from_bytes(&payload).unwrap();
        assert_eq!(frame.command.flags.no_packet_data, false);
        assert_eq!(frame.command.flags.no_tagged_fields, false);
        assert_eq!(frame.command.packet_type, Type::RxPacket);
        assert_eq!(frame.encapsulation, Some(Encapsulation::Ethernet));
        assert_eq!(frame.mode, None);
        assert_eq!(frame.tagged_fields.unwrap().as_slice(), vec![]);
        assert_eq!(frame.packet_data, Some(hex_bytes("ffffff").as_slice()));
    }

    #[test]
    fn test_empty_data() {
        let payload = hex_bytes("0100000101");
        let frame = Frame::from_bytes(&payload).unwrap();
        assert_eq!(frame.command.flags.no_packet_data, false);
        assert_eq!(frame.command.flags.no_tagged_fields, false);
        assert_eq!(frame.command.packet_type, Type::RxPacket);
        assert_eq!(frame.encapsulation, Some(Encapsulation::Ethernet));
        assert_eq!(frame.mode, None);
        assert_eq!(frame.tagged_fields.unwrap().as_slice(), vec![]);
        assert_eq!(frame.packet_data, Some(hex_bytes("").as_slice()));
    }

    #[test]
    fn test_no_data() {
        let payload = hex_bytes("0140000101");
        let frame = Frame::from_bytes(&payload).unwrap();
        assert_eq!(frame.command.flags.no_packet_data, true);
        assert_eq!(frame.command.flags.no_tagged_fields, false);
        assert_eq!(frame.command.packet_type, Type::RxPacket);
        assert_eq!(frame.encapsulation, Some(Encapsulation::Ethernet));
        assert_eq!(frame.mode, None);
        assert_eq!(frame.tagged_fields.unwrap().as_slice(), vec![]);
        assert_eq!(frame.packet_data, None);
    }
}
