use argh::FromArgs;
use endio::LERead;
use endio::LEWrite;
use lu_packets::auth::client::ClientMessage as AuthClientMessage;
use lu_packets::auth::client::LoginResponse;
use lu_packets::auth::client::LuMessage as ClientLuMessage;
use lu_packets::auth::client::Message as ClientMessage;
use lu_packets::auth::server::AuthMessage as ServerAuthMessage;
use lu_packets::auth::server::LuMessage as ServerLuMessage;
use lu_packets::auth::server::Message as ServerMessage;
use lu_packets::common::LuStrExt;
use lu_packets::common::LuVarWString;
use lu_packets::common::ServiceId;
use lu_packets::general::client::GeneralMessage as ClientGeneralMessage;
use lu_packets::general::client::Handshake as ClientHandshake;
use lu_packets::general::server::GeneralMessage as ServerGeneralMessage;
use raknet::BitStreamWrite;
use raknet::PacketHandler;
use raknet::RakPeer;
use raknet::RemoteSystem;
use raknet::SystemAddress;
use std::net::Ipv4Addr;
use std::ops::ControlFlow;
use tokio::io;
use tracing::error;
use tracing::info;
use tracing::warn;

#[derive(FromArgs)]
/// Reach new heights.
struct TestServer {
    /// the password to use
    #[argh(option, short = 'P', default = r#""3.25 ND1".to_string()"#)]
    password: String,

    /// how high to go
    #[argh(option, short = 'p', default = "1001")]
    port: u16,
}

struct BasicHandler;

impl PacketHandler for BasicHandler {
    fn on_user_packet(&mut self, mut bytes: &[u8], _conn: &mut RemoteSystem) -> ControlFlow<()> {
        match bytes.read::<ServerMessage>() {
            Ok(ServerMessage::UserMessage(ServerLuMessage::General(gmg))) => match gmg {
                ServerGeneralMessage::Handshake(h) => {
                    info!("{:?}", h);
                    let reply = ClientGeneralMessage::Handshake(ClientHandshake {
                        network_version: h.network_version,
                        service_id: ServiceId::Auth,
                    });
                    let msg = ClientMessage::UserMessage(ClientLuMessage::General(reply));
                    let mut bs = BitStreamWrite::new();
                    LEWrite::write(&mut bs, &msg).unwrap();
                    _conn.send(bs, raknet::PacketReliability::Reliable);
                }
            },
            Ok(ServerMessage::UserMessage(ServerLuMessage::Auth(amg))) => match amg {
                ServerAuthMessage::LoginRequest(l) => {
                    info!("{:?}", l);
                    let text = format!(
                        "Hi @{}! Sorry, but this server is currently under development!",
                        l.username.to_string()
                    );
                    let text = LuVarWString::try_from(text.as_str()).unwrap();
                    let reply =
                        AuthClientMessage::LoginResponse(LoginResponse::CustomMessage(text));
                    let msg = ClientMessage::UserMessage(ClientLuMessage::Client(reply));
                    let mut bs = BitStreamWrite::new();
                    LEWrite::write(&mut bs, &msg).unwrap();
                    _conn.send(bs, raknet::PacketReliability::Reliable);
                }
            },
            Ok(msg) => warn!("{:?}", msg),
            Err(e) => error!("invalid auth message: {}", e),
        }
        ControlFlow::Break(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), io::Error> {
    tracing_subscriber::fmt::init();
    let args: TestServer = argh::from_env();

    let local = SystemAddress::new(Ipv4Addr::LOCALHOST, args.port);
    let mut server = RakPeer::new(local, BasicHandler).await?;
    server.run(args.password).await?;
    Ok(())
}
