//! To communicate with a local instance of Python RNS should use a config like:
//!
//! ```text
//! [[UDP Interface]]
//! type = UDPInterface
//! enabled = yes
//! listen_ip = 0.0.0.0
//! listen_port = 4242
//! forward_ip = 127.0.0.1
//! forward_port = 4243
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::link::{Link, LinkEvent, LinkStatus};
use reticulum::destination::{DestinationName, SingleInputDestination, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::packet::PacketDataBuffer;
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    log::info!(">>> UDP LINK APP <<<");

    let id = PrivateIdentity::new_from_rand(OsRng);
    let destination =
        SingleInputDestination::new(id.clone(), DestinationName::new("example", "app"));
    let transport = Transport::new(TransportConfig::new("server", &id, true));

    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4243", Some("127.0.0.1:4242")),
        UdpInterface::spawn,
    );

    let dest = Arc::new(tokio::sync::Mutex::new(destination));

    let mut out_link_events = transport.out_link_events();

    let links = Arc::new(Mutex::new(HashMap::<
        AddressHash,
        Arc<tokio::sync::Mutex<Link>>,
    >::new()));

    // Register announce handler to automatically establish links
    {
        let transport_clone = transport.clone();
        let links_clone = links.clone();
        transport
            .register_announce_handler(
                move |destination: Arc<Mutex<SingleOutputDestination>>,
                      _app_data: PacketDataBuffer| {
                    let transport = transport_clone.clone();
                    let links = links_clone.clone();
                    tokio::spawn(async move {
                        let dest = destination.lock().await;
                        let dest_hash = dest.desc.address_hash;
                        let full_name = dest.desc.name.full_name();

                        log::debug!("Received announce from {} ({})", dest_hash, full_name);

                        let mut links_guard = links.lock().await;
                        let link = match links_guard.get(&dest_hash) {
                            Some(link) => link.clone(),
                            None => {
                                let link = transport.link(dest.desc.clone()).await;
                                links_guard.insert(dest_hash, link.clone());
                                link
                            }
                        };
                        drop(links_guard);

                        let link = link.lock().await;
                        log::info!("link {}: {:?}", link.id(), link.status());
                        if link.status() == LinkStatus::Active {
                            let packet = link.data_packet(b"foo").unwrap();
                            let _ = transport.send_packet(packet).await;
                        }
                    });
                },
            )
            .await;
    }

    loop {
        while let Ok(link_event) = out_link_events.try_recv() {
            match link_event.event {
                LinkEvent::Activated => log::info!("link {} activated", link_event.id),
                LinkEvent::Closed => log::info!("link {} closed", link_event.id),
                LinkEvent::Data(payload) => log::info!(
                    "link {} data payload: {}",
                    link_event.id,
                    std::str::from_utf8(payload.as_slice())
                        .map(str::to_string)
                        .unwrap_or_else(|_| format!("{:?}", payload.as_slice()))
                ),
                LinkEvent::Resource(_) => {
                    // Resource packets are ignored in this example.
                }
            }
        }
        transport.send_announce(&dest, None).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    //log::info!("exit");
}
