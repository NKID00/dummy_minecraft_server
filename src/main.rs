use std::{
    fmt::Display,
    io::Cursor,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use binrw::{binread, binrw, binwrite, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt};
use byteorder::{ReadBytesExt, WriteBytesExt};
use eyre::{bail, Report, Result};
use futures::{SinkExt, StreamExt};
use paste::paste;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    fs::File,
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    select, spawn,
};
#[cfg(test)]
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::{Decoder, Encoder, Framed},
};
use tracing::{debug, error, info, instrument, Level};
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[binrw]
#[brw(big)]
struct VarInt(
    #[br(parse_with(var_int_parser))]
    #[bw(write_with(var_int_writer))]
    i32,
);

impl Deref for VarInt {
    type Target = i32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for VarInt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[binrw::parser(reader)]
fn var_int_parser() -> BinResult<i32> {
    let mut buffer = [0u8];
    let mut value = 0i32;
    let mut position = 0u8;
    loop {
        reader.read_exact(&mut buffer)?;
        value |= ((buffer[0] & 0b0111_1111) as i32) << position;
        if buffer[0] & 0b1000_0000 == 0 {
            break;
        }
        position += 7;
        if position >= 32 {
            return BinResult::Err(binrw::Error::AssertFail {
                pos: 5,
                message: "VarInt too long".to_string(),
            });
        }
    }
    Ok(value)
}

#[binrw::writer(writer)]
fn var_int_writer(value: &i32) -> BinResult<()> {
    let mut value = *value;
    loop {
        if value & (!0b0111_1111i32) == 0 {
            writer.write_u8(value as u8)?;
            break;
        }
        writer.write_u8((value as u8 & 0b0111_1111) | 0b1000_0000)?;
        value = ((value as u32) >> 7) as i32;
    }
    Ok(())
}

macro_rules! impl_var_int {
    ($type:ident) => {
        paste! {
            #[binrw::parser(reader)]
            pub fn [<var_int_ $type _parser>]() -> BinResult<$type> {
                let mut buffer = [0u8];
                let mut value = 0i32;
                let mut position = 0u8;
                loop {
                    reader.read_exact(&mut buffer)?;
                    value |= ((buffer[0] & 0b0111_1111) as i32) << position;
                    if buffer[0] & 0b1000_0000 == 0 {
                        break;
                    }
                    position += 7;
                    if position >= 32 {
                        return BinResult::Err(binrw::Error::AssertFail {
                            pos: 5,
                            message: "VarInt too long".to_string(),
                        });
                    }
                }
                Ok(value as $type)
            }

            #[binrw::writer(writer)]
            pub fn [<var_int_ $type _writer>](value: &$type) -> BinResult<()> {
                let mut value = *value as i32;
                loop {
                    if value & (!0b0111_1111i32) == 0 {
                        writer.write_u8(value as u8)?;
                        break;
                    }
                    writer.write_u8((value as u8 & 0b0111_1111) | 0b1000_0000)?;
                    value = ((value as u32) >> 7) as i32;
                }
                Ok(())
            }
        }
    };
}

impl_var_int!(i8);
impl_var_int!(u8);
impl_var_int!(i16);
impl_var_int!(u16);
impl_var_int!(i32);
impl_var_int!(u32);
impl_var_int!(isize);
impl_var_int!(usize);

#[test]
fn var_int() {
    let mut buffer = Cursor::new(vec![]);
    VarInt(-1).write(&mut buffer).unwrap();
    assert_eq!(buffer.get_ref(), b"\xff\xff\xff\xff\x0f");
    buffer.set_position(0);
    assert_eq!(VarInt::read(&mut buffer).unwrap(), VarInt(-1));

    let mut buffer = Cursor::new(vec![]);
    VarInt(25565).write(&mut buffer).unwrap();
    assert_eq!(buffer.get_ref(), b"\xdd\xc7\x01");
    buffer.set_position(0);
    assert_eq!(VarInt::read(&mut buffer).unwrap(), VarInt(25565));

    for i in i32::MIN..=(i32::MIN + 10000) {
        let mut buffer = Cursor::new(vec![]);
        VarInt(i).write(&mut buffer).unwrap();
        buffer.set_position(0);
        assert_eq!(VarInt::read(&mut buffer).unwrap(), VarInt(i));
    }

    for i in (i32::MAX - 10000)..=i32::MAX {
        let mut buffer = Cursor::new(vec![]);
        VarInt(i).write(&mut buffer).unwrap();
        buffer.set_position(0);
        assert_eq!(VarInt::read(&mut buffer).unwrap(), VarInt(i));
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[binrw]
#[brw(big)]
struct VarLong(
    #[br(parse_with(var_long_parser))]
    #[bw(write_with(var_long_writer))]
    i64,
);

impl Deref for VarLong {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for VarLong {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[binrw::parser(reader)]
fn var_long_parser() -> BinResult<i64> {
    let mut buffer = [0u8];
    let mut value = 0i64;
    let mut position = 0u8;
    loop {
        reader.read_exact(&mut buffer)?;
        value |= ((buffer[0] & 0b0111_1111) as i64) << position;
        if buffer[0] & 0b1000_0000 == 0 {
            break;
        }
        position += 7;
        if position >= 64 {
            return BinResult::Err(binrw::Error::AssertFail {
                pos: 10,
                message: "VarLong too long".to_string(),
            });
        }
    }
    Ok(value)
}

#[binrw::writer(writer)]
fn var_long_writer(value: &i64) -> BinResult<()> {
    let mut value = *value;
    loop {
        if value & (!0b0111_1111i64) == 0 {
            writer.write_u8(value as u8)?;
            break;
        }
        writer.write_u8((value as u8 & 0b0111_1111) | 0b1000_0000)?;
        value = ((value as u64) >> 7) as i64;
    }
    Ok(())
}

macro_rules! impl_var_long {
    ($type:ident) => {
        paste! {
            #[binrw::parser(reader)]
            pub fn [<var_long_ $type _parser>]() -> BinResult<i64> {
                let mut buffer = [0u8];
                let mut value = 0i64;
                let mut position = 0u8;
                loop {
                    reader.read_exact(&mut buffer)?;
                    value |= ((buffer[0] & 0b0111_1111) as i64) << position;
                    if buffer[0] & 0b1000_0000 == 0 {
                        break;
                    }
                    position += 7;
                    if position >= 64 {
                        return BinResult::Err(binrw::Error::AssertFail {
                            pos: 10,
                            message: "VarLong too long".to_string(),
                        });
                    }
                }
                Ok(value)
            }

            #[binrw::writer(writer)]
            pub fn [<var_long_ $type _writer>](value: &i64) -> BinResult<()> {
                let mut value = *value;
                loop {
                    if value & (!0b0111_1111i64) == 0 {
                        writer.write_u8(value as u8)?;
                        break;
                    }
                    writer.write_u8((value as u8 & 0b0111_1111) | 0b1000_0000)?;
                    value = ((value as u64) >> 7) as i64;
                }
                Ok(())
            }
        }
    };
}

impl_var_long!(i8);
impl_var_long!(u8);
impl_var_long!(i16);
impl_var_long!(u16);
impl_var_long!(i32);
impl_var_long!(u32);
impl_var_long!(i64);
impl_var_long!(u64);
impl_var_long!(isize);
impl_var_long!(usize);

#[test]
fn var_long() {
    let mut buffer = Cursor::new(vec![]);
    VarLong(-1).write(&mut buffer).unwrap();
    assert_eq!(
        buffer.get_ref(),
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"
    );
    buffer.set_position(0);
    assert_eq!(VarLong::read(&mut buffer).unwrap(), VarLong(-1));

    let mut buffer = Cursor::new(vec![]);
    VarLong(25565).write(&mut buffer).unwrap();
    assert_eq!(buffer.get_ref(), b"\xdd\xc7\x01");
    buffer.set_position(0);
    assert_eq!(VarLong::read(&mut buffer).unwrap(), VarLong(25565));

    for i in i64::MIN..=(i64::MIN + 10000) {
        let mut buffer = Cursor::new(vec![]);
        VarLong(i).write(&mut buffer).unwrap();
        buffer.set_position(0);
        assert_eq!(VarLong::read(&mut buffer).unwrap(), VarLong(i));
    }

    for i in (i64::MAX - 10000)..=i64::MAX {
        let mut buffer = Cursor::new(vec![]);
        VarLong(i).write(&mut buffer).unwrap();
        buffer.set_position(0);
        assert_eq!(VarLong::read(&mut buffer).unwrap(), VarLong(i));
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[binrw]
#[brw(big)]
struct SizedString(
    #[br(parse_with(sized_string_parser))]
    #[bw(write_with(sized_string_writer))]
    String,
);

impl Deref for SizedString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SizedString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for SizedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", **self)
    }
}

#[binrw::parser(reader)]
fn sized_string_parser() -> BinResult<String> {
    let len: VarInt = reader.read_be()?;
    let len = *len as usize;
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer)?;
    let value = String::from_utf8(buffer).map_err(|e| binrw::Error::AssertFail {
        pos: e.utf8_error().valid_up_to() as u64,
        message: "Invalid UTF-8".to_string(),
    })?;
    Ok(value)
}

#[binrw::writer(writer)]
fn sized_string_writer(value: &String) -> BinResult<()> {
    writer.write_be(&VarInt(value.len() as i32))?;
    writer.write_all(value.as_bytes())?;
    Ok(())
}

#[test]
fn sized_string() {
    let mut buffer = Cursor::new(vec![]);
    SizedString("".to_string()).write(&mut buffer).unwrap();
    assert_eq!(buffer.get_ref(), b"\x00");
    buffer.set_position(0);
    assert_eq!(
        SizedString::read(&mut buffer).unwrap(),
        SizedString("".to_string())
    );

    let mut buffer = Cursor::new(vec![]);
    SizedString("Hello, world!".to_string())
        .write(&mut buffer)
        .unwrap();
    assert_eq!(buffer.get_ref(), b"\x0dHello, world!");
    buffer.set_position(0);
    assert_eq!(
        SizedString::read(&mut buffer).unwrap(),
        SizedString("Hello, world!".to_string())
    );

    let mut buffer = Cursor::new(vec![]);
    SizedString("a".repeat(255)).write(&mut buffer).unwrap();
    assert_eq!(
        buffer.get_ref(),
        [b"\xff\x01".to_vec(), b"a".repeat(255)].concat().as_slice()
    );
    buffer.set_position(0);
    assert_eq!(
        SizedString::read(&mut buffer).unwrap(),
        SizedString("a".repeat(255))
    );
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
#[binrw]
#[brw(big)]
struct Boolean(
    #[br(parse_with(boolean_parser))]
    #[bw(write_with(boolean_writer))]
    bool,
);

impl Deref for Boolean {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Boolean {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for Boolean {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", **self)
    }
}

#[binrw::parser(reader)]
fn boolean_parser() -> BinResult<bool> {
    match reader.read_u8()? {
        0x01 => Ok(true),
        0x00 => Ok(false),
        _ => Err(binrw::Error::AssertFail {
            pos: 0,
            message: "Invalid Boolean".to_string(),
        }),
    }
}

#[binrw::writer(writer)]
fn boolean_writer(value: &bool) -> BinResult<()> {
    writer.write_u8(match value {
        true => 0x01,
        false => 0x00,
    })?;
    Ok(())
}

#[test]
fn boolean() {
    let mut buffer = Cursor::new(vec![]);
    Boolean(true).write(&mut buffer).unwrap();
    assert_eq!(buffer.get_ref(), b"\x01");
    buffer.set_position(0);
    assert_eq!(Boolean::read(&mut buffer).unwrap(), Boolean(true));

    let mut buffer = Cursor::new(vec![]);
    Boolean(false).write(&mut buffer).unwrap();
    assert_eq!(buffer.get_ref(), b"\x00");
    buffer.set_position(0);
    assert_eq!(Boolean::read(&mut buffer).unwrap(), Boolean(false));
}

macro_rules! impl_decoder {
    ($type:ident, $body:ident) => {
        impl Decoder for $type {
            type Item = (usize, $body);
            type Error = Report;

            fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
                let mut reader = Cursor::new(&src[..]);
                let length = match VarInt::read(&mut reader) {
                    Ok(v) => v,
                    Err(binrw::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    Err(binrw::Error::Backtrace(backtrace)) => match &*backtrace.error {
                        binrw::Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            return Ok(None);
                        }
                        _ => Err(binrw::Error::Backtrace(backtrace))?,
                    },
                    Err(e) => Err(e)?,
                };
                let length = *length;
                if length < 0 {
                    bail!("packet length is negative");
                }
                if length > (1 << 21) - 1 {
                    bail!("packet too large");
                }
                let length = length as usize;
                if reader.remaining() < length {
                    return Ok(None);
                }
                // length of length field
                let length_length = reader.position() as usize;

                let mut reader = Cursor::new(&src[length_length..length_length + length]);
                let result = match $body::read(&mut reader) {
                    Ok(v) => v,
                    Err(binrw::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        bail!("packet length does not match: unexpected eof");
                    }
                    Err(binrw::Error::Backtrace(backtrace)) => match &*backtrace.error {
                        binrw::Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            bail!("packet length does not match: unexpected eof");
                        }
                        _ => Err(binrw::Error::Backtrace(backtrace))?,
                    },
                    Err(e) => Err(e)?,
                };
                if reader.has_remaining() {
                    bail!("packet length does not match: extra bytes");
                }
                src.advance(length_length + length);
                debug!("read packet: {}, {}, {:?}", length_length, length, result);
                Ok(Some((length, result)))
            }
        }
    };
}

macro_rules! impl_blank_decoder {
    ($type:ident) => {
        impl Decoder for $type {
            type Item = ();
            type Error = Report;

            fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>> {
                unimplemented!("decoding is not supported");
            }
        }
    };
}

macro_rules! impl_encoder {
    ($type:ident, $item:ident) => {
        impl Encoder<$item> for $type {
            type Error = Report;

            fn encode(&mut self, item: $item, dst: &mut BytesMut) -> Result<()> {
                let mut writer = Cursor::new(Vec::new());
                item.write(&mut writer)?;
                let length = writer.position() as usize;
                if length > (1 << 21) - 1 {
                    bail!("packet too large");
                }
                let mut length_writer = Cursor::new(Vec::new());
                VarInt(length as i32).write(&mut length_writer)?;
                dst.extend(length_writer.into_inner());
                dst.extend(writer.into_inner());
                debug!("wrote packet: {}, {:?}", length, item);
                Ok(())
            }
        }
    };
}

macro_rules! impl_blank_encoder {
    ($type:ident) => {
        impl Encoder<()> for $type {
            type Error = Report;

            fn encode(&mut self, _item: (), _dst: &mut BytesMut) -> Result<()> {
                unimplemented!("encoding is not supported");
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SHandshakingPacket {
    #[brw(magic(b"\x00"))]
    Handshake {
        #[br(parse_with(var_int_i32_parser))]
        #[bw(write_with(var_int_i32_writer))]
        protocol_version: i32,
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        server_address: String,
        server_port: u16,
        next_state: HandshakeNextState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binread]
#[brw(big)]
enum HandshakeNextState {
    #[brw(magic(b"\x01"))]
    Status,
    #[brw(magic(b"\x02"))]
    Login,
}

#[derive(Debug, Clone)]
struct HandshakingPacketCodec;
impl_decoder!(HandshakingPacketCodec, C2SHandshakingPacket);
impl_blank_encoder!(HandshakingPacketCodec);

#[tokio::test]
async fn handshaking_packet_codec() {
    let buffer =
        Cursor::new(b"\x10\x00\xfd\x05\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x01");
    let mut framed = FramedRead::new(buffer, HandshakingPacketCodec);
    assert_eq!(
        framed.next().await.unwrap().unwrap(),
        (
            16,
            C2SHandshakingPacket::Handshake {
                protocol_version: 765,
                server_address: "localhost".to_string(),
                server_port: 25565,
                next_state: HandshakeNextState::Status,
            }
        )
    );
    assert!(framed.next().await.is_none());
}

#[derive(Debug, Clone, PartialEq)]
#[binwrite]
#[brw(big)]
enum S2CStatusPacket {
    #[brw(magic(b"\x00"))]
    StatusResponse {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        json_response: String,
    },
    #[brw(magic(b"\x01"))]
    PingResponse { payload: i64 },
}

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SStatusPacket {
    #[brw(magic(b"\x00"))]
    StatusRequest {},
    #[brw(magic(b"\x01"))]
    PingRequest { payload: i64 },
}

#[derive(Debug, Clone)]
struct StatusPacketCodec;
impl_decoder!(StatusPacketCodec, C2SStatusPacket);
impl_encoder!(StatusPacketCodec, S2CStatusPacket);

#[tokio::test]
async fn status_packet_codec() {
    let buffer = Cursor::new(b"\x01\x00");
    let mut framed = FramedRead::new(buffer, StatusPacketCodec);
    assert_eq!(
        framed.next().await.unwrap().unwrap(),
        (1, C2SStatusPacket::StatusRequest {})
    );
    assert!(framed.next().await.is_none());

    let mut buffer = Cursor::new(b"aaa".to_vec());
    buffer.advance(buffer.remaining());
    assert_eq!(buffer.position() as usize, b"aaa".len());
    let mut framed = FramedWrite::new(buffer, StatusPacketCodec);
    framed
        .send(S2CStatusPacket::PingResponse { payload: 0 })
        .await
        .unwrap();
    let buffer = framed.into_inner();
    let expected = b"aaa\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00";
    assert_eq!(buffer.position() as usize, expected.len());
    assert_eq!(buffer.into_inner(), expected);
}

#[derive(Debug, Clone, PartialEq)]
#[binwrite]
#[brw(big)]
enum S2CLoginPacket {
    #[brw(magic(b"\x00"))]
    Disconnect {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        reason: String,
    },
}

/// mc 1.20.2 -
#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SLoginPacket764 {
    #[brw(magic(b"\x00"))]
    LoginStart {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        name: String,
        player_uuid: u128,
    },
}

#[derive(Debug, Clone)]
struct LoginPacketCodec764;
impl_decoder!(LoginPacketCodec764, C2SLoginPacket764);
impl_encoder!(LoginPacketCodec764, S2CLoginPacket);

/// mc 1.19.3 - 1.20.1
#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SLoginPacket761 {
    #[brw(magic(b"\x00"))]
    LoginStart {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        name: String,
        #[br(parse_with(boolean_parser))]
        #[bw(write_with(boolean_writer))]
        has_player_uuid: bool,
        #[brw(if(has_player_uuid))]
        player_uuid: u128,
    },
}

#[derive(Debug, Clone)]
struct LoginPacketCodec761;
impl_decoder!(LoginPacketCodec761, C2SLoginPacket761);
impl_encoder!(LoginPacketCodec761, S2CLoginPacket);

/// mc 1.19.1 - 1.19.2
#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SLoginPacket760 {
    #[brw(magic(b"\x00"))]
    LoginStart {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        name: String,
        #[br(parse_with(boolean_parser))]
        #[bw(write_with(boolean_writer))]
        has_sig_data: bool,
        #[brw(if(has_sig_data))]
        timestamp: u64,
        #[brw(if(has_sig_data))]
        #[br(parse_with(var_int_i32_parser))]
        #[bw(write_with(var_int_i32_writer))]
        public_key_length: i32,
        #[brw(if(has_sig_data))]
        #[br(count(public_key_length))]
        public_key: Vec<u8>,
        #[brw(if(has_sig_data))]
        #[br(parse_with(var_int_i32_parser))]
        #[bw(write_with(var_int_i32_writer))]
        signature_length: i32,
        #[brw(if(has_sig_data))]
        #[br(count(signature_length))]
        signature: Vec<u8>,
        #[br(parse_with(boolean_parser))]
        #[bw(write_with(boolean_writer))]
        has_player_uuid: bool,
        #[brw(if(has_player_uuid))]
        player_uuid: u128,
    },
}

#[derive(Debug, Clone)]
struct LoginPacketCodec760;
impl_decoder!(LoginPacketCodec760, C2SLoginPacket760);
impl_encoder!(LoginPacketCodec760, S2CLoginPacket);

/// mc 1.19
#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SLoginPacket759 {
    #[brw(magic(b"\x00"))]
    LoginStart {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        name: String,
        #[br(parse_with(boolean_parser))]
        #[bw(write_with(boolean_writer))]
        has_sig_data: bool,
        #[brw(if(has_sig_data))]
        timestamp: u64,
        #[brw(if(has_sig_data))]
        #[br(parse_with(var_int_i32_parser))]
        #[bw(write_with(var_int_i32_writer))]
        public_key_length: i32,
        #[brw(if(has_sig_data))]
        #[br(count(public_key_length))]
        public_key: Vec<u8>,
        #[brw(if(has_sig_data))]
        #[br(parse_with(var_int_i32_parser))]
        #[bw(write_with(var_int_i32_writer))]
        signature_length: i32,
        #[brw(if(has_sig_data))]
        #[br(count(signature_length))]
        signature: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct LoginPacketCodec759;
impl_decoder!(LoginPacketCodec759, C2SLoginPacket759);
impl_encoder!(LoginPacketCodec759, S2CLoginPacket);

/// mc 1.7 - 1.18.2
#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SLoginPacket0 {
    #[brw(magic(b"\x00"))]
    LoginStart {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        name: String,
    },
}

#[derive(Debug, Clone)]
struct LoginPacketCodec0;
impl_decoder!(LoginPacketCodec0, C2SLoginPacket0);
impl_encoder!(LoginPacketCodec0, S2CLoginPacket);

#[tokio::test]
async fn login_packet_codec() {
    let buffer = Cursor::new(b"\x16\x00\x04\x6a\x65\x62\x5f\x85\x3c\x80\xef\x3c\x37\x49\xfd\xaa\x49\x93\x8b\x67\x4a\xda\xe6");
    let mut framed = FramedRead::new(buffer, LoginPacketCodec764);
    assert_eq!(
        framed.next().await.unwrap().unwrap(),
        (
            22,
            C2SLoginPacket764::LoginStart {
                name: "jeb_".to_string(),
                player_uuid: 0x853c80ef3c3749fdaa49938b674adae6
            }
        )
    );
    assert!(framed.next().await.is_none());

    let mut buffer = Cursor::new(b"aaa".to_vec());
    buffer.advance(buffer.remaining());
    assert_eq!(buffer.position() as usize, b"aaa".len());
    let mut framed = FramedWrite::new(buffer, LoginPacketCodec764);
    framed
        .send(S2CLoginPacket::Disconnect {
            reason: r#"{"translate":"multiplayer.disconnect.not_whitelisted"}"#.to_string(),
        })
        .await
        .unwrap();
    let buffer = framed.into_inner();
    let expected = b"aaa\x38\x00\x36\x7b\x22\x74\x72\x61\x6e\x73\x6c\x61\x74\x65\x22\x3a\x22\x6d\x75\x6c\x74\x69\x70\x6c\x61\x79\x65\x72\x2e\x64\x69\x73\x63\x6f\x6e\x6e\x65\x63\x74\x2e\x6e\x6f\x74\x5f\x77\x68\x69\x74\x65\x6c\x69\x73\x74\x65\x64\x22\x7d";
    assert_eq!(buffer.position() as usize, expected.len());
    assert_eq!(buffer.into_inner(), expected);
}

#[derive(Debug, Clone)]
struct BlankCodec;
impl_blank_decoder!(BlankCodec);
impl_blank_encoder!(BlankCodec);

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub bind_addr: String,
    pub version: String,
    pub description: String,
    pub player_max: i32,
    pub player_online: i32,
    pub favicon: String,
    pub disconnect_reason: String,
    pub player_sample: Vec<PlayerSample>,
    #[serde(skip)]
    pub description_json: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlayerSample {
    pub name: String,
    pub id: String,
}

#[derive(Debug)]
pub struct Connection {
    pub conf: Arc<Configuration>,
    pub client_addr: SocketAddr,
    pub client_protocol_version: Option<i32>,
    pub requested_server_address: Option<String>,
    pub requested_server_port: Option<u16>,
    pub player_name: Option<String>,
    pub player_uuid: Option<u128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Handshaking,
    Status,
    Login764,
    Login761,
    Login760,
    Login759,
    Login0,
    Disconnected,
}

#[instrument(level = "info", name = "", skip_all, fields(client = client_addr.to_string()))]
async fn process_connection(conf: Arc<Configuration>, sock: TcpStream, client_addr: SocketAddr) {
    info!("connected");
    if sock.set_nodelay(true).is_err() {
        error!("failed to set nodelay");
    }
    let mut conn = Connection {
        conf,
        client_addr,
        client_protocol_version: None,
        requested_server_address: None,
        requested_server_port: None,
        player_name: None,
        player_uuid: None,
    };
    let mut state = State::Handshaking;
    let mut chan = BlankCodec.framed(sock);
    loop {
        let next_state = match state {
            State::Handshaking => {
                let mut chan_mapped = chan.map_codec(|_| HandshakingPacketCodec);
                let next_state = match state_handshaking(&mut conn, &mut chan_mapped).await {
                    Ok(state) => state,

                    Err(e) => {
                        error!("unexpected error: {}", e);
                        break;
                    }
                };
                chan = chan_mapped.map_codec(|_| BlankCodec);
                next_state
            }
            State::Status => {
                let mut chan_mapped = chan.map_codec(|_| StatusPacketCodec);
                let next_state = match state_status(&mut conn, &mut chan_mapped).await {
                    Ok(state) => state,
                    Err(e) => {
                        error!("unexpected error: {}", e);
                        break;
                    }
                };
                chan = chan_mapped.map_codec(|_| BlankCodec);
                next_state
            }
            State::Login764 => {
                let mut chan_mapped = chan.map_codec(|_| LoginPacketCodec764);
                let next_state = match state_login764(&mut conn, &mut chan_mapped).await {
                    Ok(state) => state,
                    Err(e) => {
                        error!("unexpected error: {}", e);
                        break;
                    }
                };
                chan = chan_mapped.map_codec(|_| BlankCodec);
                next_state
            }
            State::Login761 => {
                let mut chan_mapped = chan.map_codec(|_| LoginPacketCodec761);
                let next_state = match state_login761(&mut conn, &mut chan_mapped).await {
                    Ok(state) => state,
                    Err(e) => {
                        error!("unexpected error: {}", e);
                        break;
                    }
                };
                chan = chan_mapped.map_codec(|_| BlankCodec);
                next_state
            }
            State::Login760 => {
                let mut chan_mapped = chan.map_codec(|_| LoginPacketCodec760);
                let next_state = match state_login760(&mut conn, &mut chan_mapped).await {
                    Ok(state) => state,
                    Err(e) => {
                        error!("unexpected error: {}", e);
                        break;
                    }
                };
                chan = chan_mapped.map_codec(|_| BlankCodec);
                next_state
            }
            State::Login759 => {
                let mut chan_mapped = chan.map_codec(|_| LoginPacketCodec759);
                let next_state = match state_login759(&mut conn, &mut chan_mapped).await {
                    Ok(state) => state,
                    Err(e) => {
                        error!("unexpected error: {}", e);
                        break;
                    }
                };
                chan = chan_mapped.map_codec(|_| BlankCodec);
                next_state
            }
            State::Login0 => {
                let mut chan_mapped = chan.map_codec(|_| LoginPacketCodec0);
                let next_state = match state_login0(&mut conn, &mut chan_mapped).await {
                    Ok(state) => state,
                    Err(e) => {
                        error!("unexpected error: {}", e);
                        break;
                    }
                };
                chan = chan_mapped.map_codec(|_| BlankCodec);
                next_state
            }
            State::Disconnected => break,
        };
        debug!("state transition: {:?} -> {:?}", state, next_state);
        state = next_state;
    }
    info!("disconnected");
}

#[instrument(level = "info", name = "handshaking", skip_all)]
async fn state_handshaking(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, HandshakingPacketCodec>,
) -> Result<State> {
    select! {
        result = chan.next() => {
            match result {
                Some(Ok((_length, packet))) => {
                    debug!("received c2s packet {:?}", packet);
                    match packet {
                        C2SHandshakingPacket::Handshake { protocol_version, server_address, server_port, next_state } => {
                            info!("client handshake");
                            conn.client_protocol_version = Some(protocol_version);
                            conn.requested_server_address = Some(server_address.to_string());
                            conn.requested_server_port = Some(server_port);
                            match next_state {
                                HandshakeNextState::Status => {
                                    return Ok(State::Status);
                                },
                                HandshakeNextState::Login => {
                                    info!("client attempts to login");
                                    return Ok(match protocol_version {
                                        764.. => State::Login764,
                                        761..=763 => State::Login761,
                                        760 => State::Login760,
                                        759 => State::Login759,
                                        _ => State::Login0,
                                    });
                                },
                            }
                        },
                    }
                }
                Some(Err(e)) => {
                    bail!("error reading c2s packet: {}", e);
                },
                None => {
                    return Ok(State::Disconnected);
                },
            }
        }
    }
}

#[instrument(level = "info", name = "status", skip_all)]
async fn state_status(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, StatusPacketCodec>,
) -> Result<State> {
    loop {
        select! {
            result = chan.next() => {
                match result {
                    Some(Ok((_length, packet))) => {
                        debug!("received c2s packet {:?}", packet);
                        match packet {
                            C2SStatusPacket::StatusRequest {} => {
                                info!("status request");
                                chan.send(S2CStatusPacket::StatusResponse {
                                    json_response: json!({
                                        "version": {
                                            "name": conn.conf.version,
                                            "protocol": conn.client_protocol_version,
                                        },
                                        "players": {
                                            "max": conn.conf.player_max,
                                            "online": conn.conf.player_online,
                                            "sample": conn.conf.player_sample,
                                        },
                                        "description": conn.conf.description_json,
                                    }).to_string()
                                }).await?;
                            }
                            C2SStatusPacket::PingRequest { payload } => {
                                info!("ping request");
                                chan.send(S2CStatusPacket::PingResponse { payload }).await?;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        bail!("error reading c2s packet: {}", e);
                    }
                    None => {
                        return Ok(State::Disconnected);
                    }
                }
            }
        }
    }
}

#[instrument(level = "info", name = "login764", skip_all)]
async fn state_login764(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, LoginPacketCodec764>,
) -> Result<State> {
    loop {
        select! {
            result = chan.next() => {
                match result {
                    Some(Ok((_length, packet))) => {
                        debug!("received c2s packet {:?}", packet);
                        match packet {
                            C2SLoginPacket764::LoginStart { name, player_uuid } => {
                                info!("login start");
                                conn.player_name = Some(name.to_string());
                                conn.player_uuid = Some(player_uuid);
                                chan.send(S2CLoginPacket::Disconnect {
                                    reason: conn.conf.disconnect_reason.clone()
                                }).await?;
                            },
                        }
                    }
                    Some(Err(e)) => {
                        bail!("error reading c2s packet: {}", e);
                    },
                    None => {
                        return Ok(State::Disconnected);
                    },
                }
            }
        }
    }
}

#[instrument(level = "info", name = "login761", skip_all)]
async fn state_login761(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, LoginPacketCodec761>,
) -> Result<State> {
    loop {
        select! {
            result = chan.next() => {
                match result {
                    Some(Ok((_length, packet))) => {
                        debug!("received c2s packet {:?}", packet);
                        match packet {
                            C2SLoginPacket761::LoginStart { name, has_player_uuid, player_uuid } => {
                                info!("login start");
                                conn.player_name = Some(name.to_string());
                                if has_player_uuid {
                                    conn.player_uuid = Some(player_uuid);
                                }
                                chan.send(S2CLoginPacket::Disconnect {
                                    reason: conn.conf.disconnect_reason.clone()
                                }).await?;
                            },
                        }
                    }
                    Some(Err(e)) => {
                        bail!("error reading c2s packet: {}", e);
                    },
                    None => {
                        return Ok(State::Disconnected);
                    },
                }
            }
        }
    }
}

#[instrument(level = "info", name = "login760", skip_all)]
async fn state_login760(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, LoginPacketCodec760>,
) -> Result<State> {
    loop {
        select! {
            result = chan.next() => {
                match result {
                    Some(Ok((_length, packet))) => {
                        debug!("received c2s packet {:?}", packet);
                        match packet {
                            C2SLoginPacket760::LoginStart { name, has_player_uuid, player_uuid, .. } => {
                                info!("login start");
                                conn.player_name = Some(name.to_string());
                                if has_player_uuid {
                                    conn.player_uuid = Some(player_uuid);
                                }
                                chan.send(S2CLoginPacket::Disconnect {
                                    reason: conn.conf.disconnect_reason.clone()
                                }).await?;
                            },
                        }
                    }
                    Some(Err(e)) => {
                        bail!("error reading c2s packet: {}", e);
                    },
                    None => {
                        return Ok(State::Disconnected);
                    },
                }
            }
        }
    }
}

#[instrument(level = "info", name = "login759", skip_all)]
async fn state_login759(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, LoginPacketCodec759>,
) -> Result<State> {
    loop {
        select! {
            result = chan.next() => {
                match result {
                    Some(Ok((_length, packet))) => {
                        debug!("received c2s packet {:?}", packet);
                        match packet {
                            C2SLoginPacket759::LoginStart { name, .. } => {
                                info!("login start");
                                conn.player_name = Some(name.to_string());
                                chan.send(S2CLoginPacket::Disconnect {
                                    reason: conn.conf.disconnect_reason.clone()
                                }).await?;
                            },
                        }
                    }
                    Some(Err(e)) => {
                        bail!("error reading c2s packet: {}", e);
                    },
                    None => {
                        return Ok(State::Disconnected);
                    },
                }
            }
        }
    }
}

#[instrument(level = "info", name = "login0", skip_all)]
async fn state_login0(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, LoginPacketCodec0>,
) -> Result<State> {
    loop {
        select! {
            result = chan.next() => {
                match result {
                    Some(Ok((_length, packet))) => {
                        debug!("received c2s packet {:?}", packet);
                        match packet {
                            C2SLoginPacket0::LoginStart { name } => {
                                info!("login start");
                                conn.player_name = Some(name.to_string());
                                chan.send(S2CLoginPacket::Disconnect {
                                    reason: conn.conf.disconnect_reason.clone()
                                }).await?;
                            },
                        }
                    }
                    Some(Err(e)) => {
                        bail!("error reading c2s packet: {}", e);
                    },
                    None => {
                        return Ok(State::Disconnected);
                    },
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut conf_string = String::new();
    File::open("dummy_minecraft_server.toml")
        .await
        .unwrap()
        .read_to_string(&mut conf_string)
        .await
        .unwrap();
    let mut conf: Configuration = toml::from_str(&conf_string).unwrap();
    conf.description_json = serde_json::from_str(&conf.description).unwrap();
    let conf = Arc::new(conf);
    if cfg!(debug_assertions) {
        tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_target(true)
            .with_span_events(FmtSpan::ACTIVE)
            .with_file(true)
            .with_line_number(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .with_target(false)
            .init();
    }
    debug!("starting up");
    let listener = TcpListener::bind(conf.bind_addr.as_str()).await?;
    info!("listening on {}", conf.bind_addr.as_str());
    loop {
        let (sock, client_addr) = listener.accept().await?;
        spawn(process_connection(conf.clone(), sock, client_addr));
    }
}
