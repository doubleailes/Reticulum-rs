/// Example demonstrating a destination that can receive link requests
/// 
/// This example creates a transport with a registered destination using add_destination()
/// and sends an announce. It then waits for link requests and handles them appropriately.
/// 
/// With the fix in place, LinkRequest packets are no longer filtered as duplicates,
/// ensuring that link establishment works correctly.

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let mut transport = Transport::new(TransportConfig::default());

    log::info!("Connecting to local rnsd at 127.0.0.1:4242");
    transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    // Wait a moment for connection to establish
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Create identity and destination
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let destination = transport
        .add_destination(identity, DestinationName::new("example", "link_receiver"))
        .await;

    let dest_hash = destination.lock().await.desc.address_hash;
    log::info!("Destination created with hash: {}", dest_hash);

    // Send announce
    log::info!("Sending announce...");
    transport.send_announce(&destination, Some(b"test app data")).await;

    // Listen for incoming link events
    log::info!("Listening for incoming links...");
    let mut link_events = transport.in_link_events();

    tokio::spawn(async move {
        loop {
            match link_events.recv().await {
                Ok(event) => {
                    log::info!("Link event received: link_id={}, address_hash={}", 
                              event.id, event.address_hash);
                }
                Err(e) => {
                    log::error!("Error receiving link event: {}", e);
                    break;
                }
            }
        }
    });

    // Keep running
    log::info!("Ready to receive link requests. Press Ctrl+C to exit.");
    let _ = tokio::signal::ctrl_c().await;
    log::info!("Shutting down...");
}
