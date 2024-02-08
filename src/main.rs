use std::{
    io::Cursor, net::SocketAddr, ops::{Deref, DerefMut}, sync::Arc
};

use binrw::{binrw, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use eyre::{bail, Result};
use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
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
}

#[binrw]
#[brw(big)]
struct VarLong(
    #[br(parse_with(var_long_parser))]
    #[bw(write_with(var_long_writer))]
    i64,
);

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

#[binrw()]
enum HandshakePacket {
    Handshake {},
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
