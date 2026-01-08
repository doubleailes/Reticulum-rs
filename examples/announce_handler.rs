use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::destination::SingleOutputDestination;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::packet::PacketDataBuffer;
use reticulum::transport::{AnnounceHandler, Transport, TransportConfig};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

// Example 1: Handler with aspect filter (like LXMF delivery handler)
struct LXMFDeliveryHandler {
    name: String,
}

impl LXMFDeliveryHandler {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl AnnounceHandler for LXMFDeliveryHandler {
    fn aspect_filter(&self) -> Option<&str> {
        Some("delivery") // Only receive "*.delivery" announces
    }

    fn handle_announce(
        &self,
        destination: Arc<Mutex<SingleOutputDestination>>,
        app_data: PacketDataBuffer,
    ) {
        let name = self.name.clone();

        tokio::spawn(async move {
            let dest = destination.lock().await;
            let dest_hash = dest.desc.address_hash;
            let full_name = dest.desc.name.full_name();

            log::info!(
                "[{}] 📬 Delivery announce from: {} ({})",
                name,
                dest_hash,
                full_name
            );
            log::info!(
                "   App data: {}",
                String::from_utf8_lossy(app_data.as_slice())
            );
        });
    }
}

// Example 2: Handler with different aspect filter
struct LXMFPropagationHandler {
    name: String,
}

impl LXMFPropagationHandler {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl AnnounceHandler for LXMFPropagationHandler {
    fn aspect_filter(&self) -> Option<&str> {
        Some("propagation") // Only receive "*.propagation" announces
    }

    fn receive_path_responses(&self) -> bool {
        true // Accept path responses
    }

    fn handle_announce(
        &self,
        destination: Arc<Mutex<SingleOutputDestination>>,
        app_data: PacketDataBuffer,
    ) {
        let name = self.name.clone();

        tokio::spawn(async move {
            let dest = destination.lock().await;
            let dest_hash = dest.desc.address_hash;
            let full_name = dest.desc.name.full_name();

            log::info!(
                "[{}] 🌐 Propagation announce from: {} ({})",
                name,
                dest_hash,
                full_name
            );
            log::info!(
                "   App data: {}",
                String::from_utf8_lossy(app_data.as_slice())
            );
        });
    }
}

// Example 3: Trait-based handler with state (no aspect filter)
struct StatsAnnounceHandler {
    name: String,
    count: Arc<Mutex<u32>>,
}

impl StatsAnnounceHandler {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            count: Arc::new(Mutex::new(0)),
        }
    }
}

impl AnnounceHandler for StatsAnnounceHandler {
    fn handle_announce(
        &self,
        destination: Arc<Mutex<SingleOutputDestination>>,
        app_data: PacketDataBuffer,
    ) {
        let name = self.name.clone();
        let count = self.count.clone();

        tokio::spawn(async move {
            let mut counter = count.lock().await;
            *counter += 1;

            let dest = destination.lock().await;
            let dest_hash = dest.desc.address_hash;
            let full_name = dest.desc.name.full_name();

            log::info!(
                "[{}] 📊 Announce #{} from: {} ({})",
                name,
                counter,
                dest_hash,
                full_name
            );
            log::info!(
                "   App data: {}",
                String::from_utf8_lossy(app_data.as_slice())
            );
        });
    }

    fn should_handle(&self, _destination_hash: &AddressHash) -> bool {
        // This handler processes all announces
        true
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!(">>> ANNOUNCE HANDLER EXAMPLE <<<");

    // Create transport
    let transport = Transport::new(TransportConfig::new(
        "example",
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    ));

    // Example 1: Register LXMF delivery handler (aspect: "delivery")
    let delivery_handler = LXMFDeliveryHandler::new("DeliveryHandler");
    transport.register_announce_handler(delivery_handler).await;

    // Example 2: Register LXMF propagation handler (aspect: "propagation")
    let propagation_handler = LXMFPropagationHandler::new("PropagationHandler");
    transport
        .register_announce_handler(propagation_handler)
        .await;

    // Example 3: Register stats handler (no aspect filter - receives all)
    let stats_handler = StatsAnnounceHandler::new("StatsHandler");
    transport.register_announce_handler(stats_handler).await;

    // Example 4: Register a simple closure handler
    transport
        .register_announce_handler(
            |destination: Arc<Mutex<SingleOutputDestination>>, app_data: PacketDataBuffer| {
                tokio::spawn(async move {
                    let dest = destination.lock().await;
                    let dest_hash = dest.desc.address_hash;
                    let full_name = dest.desc.name.full_name();
                    log::info!(
                        "📢 [ClosureHandler] Received announce from: {} ({})",
                        dest_hash,
                        full_name
                    );
                    log::info!(
                        "   App data: {}",
                        String::from_utf8_lossy(app_data.as_slice())
                    );
                });
            },
        )
        .await;

    // Connect to Amsterdam test server to receive announces
    let _ = transport.iface_manager().lock().await.spawn(
        TcpClient::new("amsterdam.connect.reticulum.network:4965"),
        TcpClient::spawn,
    );

    // Create a destination and announce it periodically
    tokio::spawn({
        let mut transport = transport;
        async move {
            let identity = PrivateIdentity::new_from_rand(OsRng);

            // Create a delivery destination
            let delivery_dest_name = DestinationName::new("lxmf", "delivery");
            let delivery_dest = transport
                .add_destination(identity.clone(), delivery_dest_name)
                .await;
            let delivery_hash = delivery_dest.lock().await.desc.address_hash;
            log::info!("Created delivery destination: {}", delivery_hash);

            // Create a propagation destination
            let prop_dest_name = DestinationName::new("lxmf", "propagation");
            let prop_dest = transport
                .add_destination(PrivateIdentity::new_from_rand(OsRng), prop_dest_name)
                .await;
            let prop_hash = prop_dest.lock().await.desc.address_hash;
            log::info!("Created propagation destination: {}", prop_hash);

            loop {
                sleep(Duration::from_secs(30)).await;

                log::info!("Sending delivery announce...");
                transport
                    .send_announce(&delivery_dest, Some(b"Delivery node ready"))
                    .await;

                sleep(Duration::from_secs(5)).await;

                log::info!("Sending propagation announce...");
                transport
                    .send_announce(&prop_dest, Some(b"Propagation node active"))
                    .await;
            }
        }
    });

    log::info!("Press Ctrl+C to exit");
    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
