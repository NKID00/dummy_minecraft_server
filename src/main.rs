use std::{
    fmt::Display,
    io::Cursor,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use binrw::{binread, binrw, binwrite, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt};
use byteorder::WriteBytesExt;
use eyre::{bail, Report, Result};
use futures::{SinkExt, StreamExt};
use paste::paste;
use serde_json::json;
use tokio::{
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

macro_rules! impl_decoder {
    ($type:ident, $item:ident, $body:ident) => {
        impl Decoder for $type {
            type Item = $item;
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
                Ok(Some($item {
                    length,
                    body: result,
                }))
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
struct C2SHandshakingPacket {
    length: usize,
    body: C2SHandshakingPacketBody,
}

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SHandshakingPacketBody {
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
impl_decoder!(
    HandshakingPacketCodec,
    C2SHandshakingPacket,
    C2SHandshakingPacketBody
);
impl_blank_encoder!(HandshakingPacketCodec);

#[tokio::test]
async fn handshaking_packet_codec() {
    let buffer =
        Cursor::new(b"\x10\x00\xfd\x05\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x01");
    let mut framed = FramedRead::new(buffer, HandshakingPacketCodec);
    assert_eq!(
        framed.next().await.unwrap().unwrap(),
        C2SHandshakingPacket {
            length: 16,
            body: C2SHandshakingPacketBody::Handshake {
                protocol_version: 765,
                server_address: "localhost".to_string(),
                server_port: 25565,
                next_state: HandshakeNextState::Status,
            }
        }
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
struct C2SStatusPacket {
    length: usize,
    body: C2SStatusPacketBody,
}

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SStatusPacketBody {
    #[brw(magic(b"\x00"))]
    StatusRequest {},
    #[brw(magic(b"\x01"))]
    PingRequest { payload: i64 },
}

#[derive(Debug, Clone)]
struct StatusPacketCodec;
impl_decoder!(StatusPacketCodec, C2SStatusPacket, C2SStatusPacketBody);
impl_encoder!(StatusPacketCodec, S2CStatusPacket);

#[tokio::test]
async fn status_packet_codec() {
    let buffer = Cursor::new(b"\x01\x00");
    let mut framed = FramedRead::new(buffer, StatusPacketCodec);
    assert_eq!(
        framed.next().await.unwrap().unwrap(),
        C2SStatusPacket {
            length: 1,
            body: C2SStatusPacketBody::StatusRequest {}
        }
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

#[derive(Debug, Clone, PartialEq)]
struct C2SLoginPacket {
    length: usize,
    body: C2SLoginPacketBody,
}

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SLoginPacketBody {
    #[brw(magic(b"\x00"))]
    LoginStart {
        #[br(parse_with(sized_string_parser))]
        #[bw(write_with(sized_string_writer))]
        name: String,
        player_uuid: u128,
    },
}

#[derive(Debug, Clone)]
struct LoginPacketCodec;
impl_decoder!(LoginPacketCodec, C2SLoginPacket, C2SLoginPacketBody);
impl_encoder!(LoginPacketCodec, S2CLoginPacket);

#[tokio::test]
async fn login_packet_codec() {
    let buffer = Cursor::new(b"\x16\x00\x04\x6a\x65\x62\x5f\x85\x3c\x80\xef\x3c\x37\x49\xfd\xaa\x49\x93\x8b\x67\x4a\xda\xe6");
    let mut framed = FramedRead::new(buffer, LoginPacketCodec);
    assert_eq!(
        framed.next().await.unwrap().unwrap(),
        C2SLoginPacket {
            length: 22,
            body: C2SLoginPacketBody::LoginStart {
                name: "jeb_".to_string(),
                player_uuid: 0x853c80ef3c3749fdaa49938b674adae6
            }
        }
    );
    assert!(framed.next().await.is_none());

    let mut buffer = Cursor::new(b"aaa".to_vec());
    buffer.advance(buffer.remaining());
    assert_eq!(buffer.position() as usize, b"aaa".len());
    let mut framed = FramedWrite::new(buffer, LoginPacketCodec);
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

#[derive(Debug)]
pub struct Configuration {
    pub addr: String,
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
    Login,
    Disconnected,
}

#[derive(Debug)]
enum StatefulChannel {
    Handshaking {
        chan: Framed<TcpStream, HandshakingPacketCodec>,
    },
    Status {
        chan: Framed<TcpStream, StatusPacketCodec>,
    },
    Login {
        chan: Framed<TcpStream, LoginPacketCodec>,
    },
}

#[instrument(level = "info", name = "", skip_all, fields(client = client_addr.to_string()))]
async fn process_connection(conf: Arc<Configuration>, sock: TcpStream, client_addr: SocketAddr) {
    info!("connected");
    if let Err(_) = sock.set_nodelay(true) {
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
    let mut stateful_chan = StatefulChannel::Handshaking {
        chan: HandshakingPacketCodec.framed(sock),
    };
    loop {
        match stateful_chan {
            StatefulChannel::Handshaking { mut chan } => {
                match state_handshaking(&mut conn, &mut chan).await {
                    Ok(State::Status) => {
                        info!("state transition: Handshaking -> Status");
                        stateful_chan = StatefulChannel::Status {
                            chan: chan.map_codec(|_| StatusPacketCodec),
                        };
                        continue;
                    }
                    Ok(State::Login) => {
                        info!("state transition: Handshaking -> Login");
                        stateful_chan = StatefulChannel::Login {
                            chan: chan.map_codec(|_| LoginPacketCodec),
                        };
                        continue;
                    }
                    Ok(State::Disconnected) => {}
                    Err(e) => {
                        error!("unexpected error: {}", e);
                    }
                    _ => unreachable!(),
                }
                break;
            }
            StatefulChannel::Status { mut chan } => {
                match state_status(&mut conn, &mut chan).await {
                    Ok(State::Disconnected) => {}
                    Err(e) => {
                        error!("unexpected error: {}", e);
                    }
                    _ => unreachable!(),
                }
                break;
            }
            StatefulChannel::Login { mut chan } => {
                match state_login(&mut conn, &mut chan).await {
                    Ok(State::Disconnected) => {}
                    Err(e) => {
                        error!("unexpected error: {}", e);
                    }
                    _ => unreachable!(),
                }
                break;
            }
        }
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
                Some(Ok(packet)) => {
                    debug!("received c2s packet {:?}", packet.body);
                    match packet.body {
                        C2SHandshakingPacketBody::Handshake { protocol_version, server_address, server_port, next_state } => {
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
                                    return Ok(State::Login);
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
                    Some(Ok(packet)) => {
                        debug!("received c2s packet {:?}", packet.body);
                        match packet.body {
                            C2SStatusPacketBody::StatusRequest {} => {
                                info!("status request");
                                chan.send(S2CStatusPacket::StatusResponse {
                                    json_response: json!({
                                        "version": {
                                            "name":"Minecraft: Dummy Edition",
                                            "protocol": conn.client_protocol_version
                                        },
                                        "players": {
                                            "max": -2147483648,
                                            "online":-2147483648,
                                        },
                                        "description": {
                                            "text": "Minecraft: Dummy Edition"
                                        }
                                    }).to_string()
                                }).await?;
                            }
                            C2SStatusPacketBody::PingRequest { payload } => {
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

#[instrument(level = "info", name = "login", skip_all)]
async fn state_login(
    conn: &mut Connection,
    chan: &mut Framed<TcpStream, LoginPacketCodec>,
) -> Result<State> {
    loop {
        select! {
            result = chan.next() => {
                match result {
                    Some(Ok(packet)) => {
                        debug!("received c2s packet {:?}", packet.body);
                        match packet.body {
                            C2SLoginPacketBody::LoginStart { name, player_uuid } => {
                                info!("login start");
                                conn.player_name = Some(name.to_string());
                                conn.player_uuid = Some(player_uuid);
                                chan.send(S2CLoginPacket::Disconnect {
                                    reason: json!({
                                        "translate": "multiplayer.disconnect.incompatible",
                                        "with": [
                                            "Minecraft: Dummy Edition"
                                        ]
                                    }).to_string()
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
    let conf = Configuration {
        addr: "0.0.0.0:25565".to_string(),
    };
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
    let listener = TcpListener::bind(conf.addr.as_str()).await?;
    info!("listening on {}", conf.addr.as_str());
    loop {
        let (sock, client_addr) = listener.accept().await?;
        spawn(process_connection(conf.clone(), sock, client_addr));
    }
}
