use std::{
    borrow::Borrow,
    io::{Cursor, Seek},
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use binrw::{binread, binrw, binwrite, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt};
use byteorder::WriteBytesExt;
use eyre::{bail, eyre, Report, Result};
use futures::{FutureExt, SinkExt, StreamExt};
use tokio::{
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    select, spawn,
    time::sleep,
};
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::{Decoder, Encoder, Framed, FramedRead, FramedWrite},
};
use tracing::{debug, error, info, instrument, Instrument, Level, Subscriber};
use tracing_subscriber::{fmt::format::FmtSpan, util::SubscriberInitExt};

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
        protocol_version: VarInt,
        server_address: SizedString,
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
                protocol_version: VarInt(765),
                server_address: SizedString("localhost".to_string()),
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
    StatusResponse { json_response: SizedString },
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
    assert_eq!(
        buffer.position() as usize,
        b"aaa\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00".len()
    );
    assert_eq!(
        buffer.into_inner(),
        b"aaa\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    );
}

#[derive(Debug)]
struct Configuration {
    addr: String,
}

#[derive(Debug)]
struct Connection {
    conf: Arc<Configuration>,
    client_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Handshaking,
    Status,
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
}

#[instrument(level = "info", name = "", skip_all, fields(client = client_addr.to_string()))]
async fn process_connection(conf: Arc<Configuration>, sock: TcpStream, client_addr: SocketAddr) {
    info!("connected");
    if let Err(_) = sock.set_nodelay(true) {
        error!("failed to set nodelay");
    }
    let mut conn = Connection { conf, client_addr };
    let mut stateful_chan = StatefulChannel::Handshaking {
        chan: HandshakingPacketCodec.framed(sock),
    };
    loop {
        match stateful_chan {
            StatefulChannel::Handshaking { mut chan } => {
                match state_handshaking(&mut conn, &mut chan).await {
                    Ok(State::Handshaking) => {
                        error!("unexpected state transition: Handshaking -> Handshaking");
                    }
                    Ok(State::Status) => {
                        info!("state transition: Handshaking -> Status");
                        stateful_chan = StatefulChannel::Status {
                            chan: chan.map_codec(|_| StatusPacketCodec),
                        };
                        continue;
                    }
                    Ok(State::Disconnected) => {}
                    Err(e) => {
                        error!("unexpected error: {}", e);
                    }
                }
                break;
            }
            StatefulChannel::Status { mut chan } => {
                match state_status(&mut conn, &mut chan).await {
                    Ok(State::Handshaking) => {
                        error!("unexpected state transition: Status -> Handshaking");
                    }
                    Ok(State::Status) => {
                        error!("unexpected state transition: Status -> Status");
                    }
                    Ok(State::Disconnected) => {}
                    Err(e) => {
                        error!("unexpected error: {}", e);
                    }
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
                            match next_state {
                                HandshakeNextState::Status => {
                                    return Ok(State::Status);
                                },
                                HandshakeNextState::Login => {
                                    info!("client attempts to login");
                                    return Ok(State::Disconnected);
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
                                chan.send(S2CStatusPacket::StatusResponse { json_response: SizedString(r#"{"version":{"name":"Minecraft: Dummy Edition","protocol":765},"players":{"max":-2147483648,"online":-2147483648,"sample":[]},"description":{"text":"Minecraft: Dummy Edition"}}"#.to_string()) }).await?;
                            },
                            C2SStatusPacketBody::PingRequest { payload } => {
                                info!("ping request");
                                chan.send(S2CStatusPacket::PingResponse { payload }).await?;
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
        addr: "127.0.0.1:25565".to_string(),
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
