use std::{
    borrow::Borrow,
    io::Cursor,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use binrw::{binread, binrw, binwrite, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt};
use byteorder::WriteBytesExt;
use eyre::{eyre, Report, Result};
use futures::StreamExt;
use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
};
use tokio_util::{
    bytes::{Buf, BytesMut},
    codec::{Decoder, Encoder, FramedRead},
};
use tracing::info;

struct Configuration {
    addr: String,
}

struct Connection {
    conf: Arc<Configuration>,
    sock: TcpStream,
    client_addr: SocketAddr,
    state: ConnectionState,
}

enum ConnectionState {
    Handshake,
    Login,
    Ping,
}

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
    writer.write(value.as_bytes())?;
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

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
struct C2SHandshakingPacket {
    #[brw(assert(*length > 0 && *length < (1<<21) - 1))]
    length: VarInt,
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
        #[brw(assert(*next_state == 0x01 || *next_state == 0x02))]
        next_state: VarInt,
    },
}

#[derive(Debug, Clone, PartialEq)]
#[binwrite]
#[brw(big)]
struct S2CStatusPacket {
    #[brw(assert(**length > 0 && **length < (1<<21) - 1))]
    length: VarInt,
    body: S2CStatusPacketBody,
}

#[derive(Debug, Clone, PartialEq)]
#[binwrite]
#[brw(big)]
enum S2CStatusPacketBody {
    #[brw(magic(b"\x00"))]
    StatusResponse { json_response: SizedString },
    #[brw(magic(b"\x01"))]
    PingResponse { payload: i64 },
}

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
struct C2SStatusPacket {
    #[brw(assert(*length > 0 && *length < (1<<21) - 1))]
    length: VarInt,
    body: C2SStatusPacketBody,
}

#[derive(Debug, Clone, PartialEq)]
#[binread]
#[brw(big)]
enum C2SStatusPacketBody {
    #[brw(magic(b"\x00"))]
    StatusRequest {},
    #[brw(magic(b"\x00"))]
    PingRequest { payload: i64 },
}

struct HandshakingPacketCodec;

impl Decoder for HandshakingPacketCodec {
    type Item = C2SHandshakingPacket;
    type Error = Report;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        let mut reader = Cursor::new(&src[..]);
        reader
            .read_be::<C2SHandshakingPacket>()
            .map(|packet| Some(packet))
            .or_else(|e| match e {
                binrw::Error::Io(e) => Err(eyre!(e)),
                binrw::Error::Backtrace(backtrace) => match backtrace.error.borrow() {
                    binrw::Error::Io(_) => Err(eyre!(backtrace)),
                    _ => Err(eyre!(backtrace)),
                },
                e => Err(eyre!(e)),
            })
    }
}

#[tokio::test]
async fn handshaking_packet_codec() {
    let buffer =
        Cursor::new(b"\x10\x00\xfd\x05\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x01");
    let mut framed = FramedRead::new(buffer, HandshakingPacketCodec);
    let result = framed.next().await.unwrap().unwrap();
    assert_eq!(
        result,
        C2SHandshakingPacket {
            length: VarInt(16),
            body: C2SHandshakingPacketBody::Handshake {
                protocol_version: VarInt(765),
                server_address: SizedString("localhost".to_string()),
                server_port: 25565,
                next_state: VarInt(1)
            }
        }
    );
}

async fn process_connection(conf: Arc<Configuration>, sock: TcpStream, client_addr: SocketAddr) {
    let conn = Connection {
        conf,
        sock,
        client_addr,
        state: ConnectionState::Handshake,
    };
    info!("Connected from {}", conn.client_addr);
    loop {}
}

#[tokio::main]
async fn main() -> Result<()> {
    let conf = Configuration {
        addr: "127.0.0.1:25565".to_string(),
    };
    let conf = Arc::new(conf);
    tracing_subscriber::fmt()
        .with_max_level(if cfg!(debug_assertions) {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .init();
    let listener = TcpListener::bind(conf.addr.as_str()).await?;
    info!("Listening on {}", conf.addr.as_str());
    loop {
        let (sock, client_addr) = listener.accept().await?;
        spawn(process_connection(conf.clone(), sock, client_addr));
    }
}
