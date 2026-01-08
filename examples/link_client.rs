use rand_core::OsRng;
use std::sync::Arc;

use reticulum::destination::{DestinationName, SingleOutputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::packet::PacketDataBuffer;
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut transport = Transport::new(TransportConfig::default());

    log::info!("start tcp app");

    {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);
    }

    let identity = PrivateIdentity::new_from_name("link-example");

    let in_destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "linkexample"),
        )
        .await;

    let packet = in_destination.lock().await.announce(OsRng, None).unwrap();
    let _ = transport.send_packet(packet).await;

    // Register announce handler to automatically establish links
    let transport_clone = transport.clone();
    transport
        .register_announce_handler(
            move |destination: Arc<Mutex<SingleOutputDestination>>, _app_data: PacketDataBuffer| {
                let transport = transport_clone.clone();
                tokio::spawn(async move {
                    let dest = destination.lock().await;
                    let dest_hash = dest.desc.address_hash;
                    let full_name = dest.desc.name.full_name();

                    log::debug!("destination announce {} ({})", dest_hash, full_name);

                    let _link = transport.link(dest.desc.clone()).await;
                });
            },
        )
        .await;

    let _ = tokio::signal::ctrl_c().await;
}
