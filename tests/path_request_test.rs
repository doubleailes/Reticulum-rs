use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    packet::PacketDataBuffer,
    transport::{AnnounceHandler, Transport, TransportConfig},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

async fn build_transport(name: &str, server_addr: &str, client_addr: &[&str]) -> Transport {
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    ));

    transport.iface_manager().lock().await.spawn(
        TcpServer::new(server_addr, transport.iface_manager()),
        TcpServer::spawn,
    );

    for &addr in client_addr {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(addr), TcpClient::spawn);
    }

    log::info!("test: transport {} created", name);

    transport
}

// Test handler that tracks announces
struct TestAnnounceHandler {
    received_count: Arc<Mutex<usize>>,
    aspect_filter: Option<String>,
}

impl TestAnnounceHandler {
    fn new(aspect_filter: Option<&str>) -> Self {
        Self {
            received_count: Arc::new(Mutex::new(0)),
            aspect_filter: aspect_filter.map(|s| s.to_string()),
        }
    }
}

impl AnnounceHandler for TestAnnounceHandler {
    fn handle_announce(
        &self,
        destination: Arc<Mutex<reticulum::destination::SingleOutputDestination>>,
        app_data: PacketDataBuffer,
    ) {
        let received_count = self.received_count.clone();
        
        tokio::spawn(async move {
            let dest = destination.lock().await;
            let dest_hash = dest.desc.address_hash;
            let full_name = dest.desc.name.full_name();
            
            let mut count = received_count.lock().await;
            *count += 1;
            
            log::info!(
                "TestHandler: Received announce #{} from {} ({})",
                *count,
                dest_hash,
                full_name
            );
            log::info!(
                "  App data: {}",
                String::from_utf8_lossy(app_data.as_slice())
            );
        });
    }

    fn aspect_filter(&self) -> Option<&str> {
        self.aspect_filter.as_deref()
    }

    fn receive_path_responses(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn test_path_request_response() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .is_test(true)
        .try_init();

    // Create two transports connected via TCP
    let mut transport_a = build_transport("a", "127.0.0.1:9091", &[]).await;
    let transport_b = build_transport("b", "127.0.0.1:9092", &["127.0.0.1:9091"]).await;

    // Wait for connection to establish
    sleep(Duration::from_secs(1)).await;

    // Create a destination on transport A
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let dest_name = DestinationName::new("test", "destination");
    let destination_a = transport_a
        .add_destination(identity_a, dest_name)
        .await;
    let dest_hash = destination_a.lock().await.desc.address_hash;

    log::info!("Created destination on transport A: {}", dest_hash);

    // Register an announce handler on transport B
    let handler = TestAnnounceHandler::new(None);
    let handler_counts = handler.received_count.clone();
    transport_b.register_announce_handler(handler).await;

    // Send a regular announce from transport A
    log::info!("Sending regular announce from transport A");
    transport_a.send_announce(&destination_a, Some(b"test announce")).await;

    // Wait for the announce to propagate
    sleep(Duration::from_secs(2)).await;

    // Check that the handler was called
    let regular_count = *handler_counts.lock().await;
    log::info!("Handler received {} regular announces", regular_count);
    assert!(regular_count > 0, "Handler should receive regular announce");

    // Now request a path from transport B
    log::info!("Requesting path from transport B to destination {}", dest_hash);
    transport_b.request_path(&dest_hash, None).await;

    // Wait for the path response
    sleep(Duration::from_secs(2)).await;

    // Check that the handler was called again for the path response
    let total_count = *handler_counts.lock().await;
    log::info!("Handler received {} total announces", total_count);
    
    // We should have received at least 2 announces: the regular one and the path response
    assert!(
        total_count >= 2,
        "Handler should receive both regular and path response announces (got {})",
        total_count
    );

    log::info!("Path request/response test completed successfully!");
}

#[tokio::test]
async fn test_path_request_response_with_multiple_destinations() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .is_test(true)
        .try_init();

    // Create two transports connected via TCP
    let mut transport_a = build_transport("a", "127.0.0.1:9093", &[]).await;
    let transport_b = build_transport("b", "127.0.0.1:9094", &["127.0.0.1:9093"]).await;

    // Wait for connection to establish
    sleep(Duration::from_secs(1)).await;

    // Create multiple destinations with different aspects on transport A
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let dest1_name = DestinationName::new("test", "destination1");
    let dest1 = transport_a
        .add_destination(identity_a.clone(), dest1_name)
        .await;
    let dest1_hash = dest1.lock().await.desc.address_hash;

    let dest2_name = DestinationName::new("test", "destination2");
    let dest2 = transport_a
        .add_destination(PrivateIdentity::new_from_rand(OsRng), dest2_name)
        .await;
    let dest2_hash = dest2.lock().await.desc.address_hash;

    log::info!("Created destination 1: {}", dest1_hash);
    log::info!("Created destination 2: {}", dest2_hash);

    // Register an announce handler on transport B (no aspect filter)
    let handler = TestAnnounceHandler::new(None);
    let counts = handler.received_count.clone();
    transport_b.register_announce_handler(handler).await;

    // Request paths from transport B (without sending regular announces first)
    log::info!("Requesting path to destination 1");
    transport_b.request_path(&dest1_hash, None).await;

    sleep(Duration::from_secs(1)).await;

    log::info!("Requesting path to destination 2");
    transport_b.request_path(&dest2_hash, None).await;

    // Wait for responses
    sleep(Duration::from_secs(2)).await;

    // Check that both path response announces were received
    let total_count = *counts.lock().await;
    log::info!("Handler received {} announces total", total_count);
    
    assert!(
        total_count >= 2,
        "Handler should receive path response announces for both destinations"
    );

    log::info!("Multiple destination path request test completed successfully!");
}
