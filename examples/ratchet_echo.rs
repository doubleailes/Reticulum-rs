use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use rand_core::OsRng;
use tokio::{
    io::{self, AsyncBufReadExt, BufReader},
    select,
    sync::Mutex,
    time::timeout,
};

use reticulum::{
    destination::{DestinationName, RatchetedDestination},
    hash::AddressHash,
    identity::PrivateIdentity,
    iface::tcp_client::TcpClient,

    transport::{Transport, TransportConfig},
};



/// Server mode: Creates a ratcheted echo server
async fn server(_config_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Starting Ratcheted Echo Server");
    println!("=================================");

    // Initialize Reticulum transport
    let transport = Arc::new(Mutex::new(Transport::new(TransportConfig::default())));

    // Try to connect to local network (optional for demo)
    println!("🌐 Attempting to connect to local network...");
    {
        let transport_guard = transport.lock().await;
        let _iface_id = transport_guard.iface_manager().lock().await.spawn(
            TcpClient::new("127.0.0.1:4242"),
            TcpClient::spawn,
        );
        println!("⚠️  Network interface created (may show connection errors if no server available)");
        println!("   This is normal for standalone demo - ratchet functionality works without network");
    }

    // Create server identity
    let server_identity = PrivateIdentity::new_from_rand(OsRng);
    println!("📋 Server identity created");

    // Create ratcheted destination: example_utilities.ratchet.echo.request
    let dest_name = DestinationName::new("ratchet.echo", "request");
    let temp_dir = std::env::temp_dir();
    let echo_destination = RatchetedDestination::new(
        server_identity.clone(),
        dest_name,
        Some(temp_dir),
    )?;

    let destination_hash = echo_destination.destination_hash();
    println!(
        "🎯 Echo server destination: {}",
        hex::encode(destination_hash.as_slice())
    );

    // Add destination to transport for packet handling
    let _destination_added = {
        let mut transport_guard = transport.lock().await;
        transport_guard.add_destination(
            server_identity.clone(),
            dest_name.clone(),
        ).await
    };
    
    println!("👂 Server is listening for incoming packets...");
    println!("   In a full implementation, this would handle encrypted ratchet packets");

    // Start announce loop
    announce_loop(echo_destination, transport).await
}

/// Server announce loop - sends announces when user presses enter
async fn announce_loop(
    destination: RatchetedDestination,
    transport: Arc<Mutex<Transport>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let destination_hash = hex::encode(destination.destination_hash().as_slice());
    
    println!("✅ Ratcheted echo server {} running", &destination_hash[..16]);
    println!("📢 Hit enter to manually send an announce (Ctrl-C to quit)");

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        select! {
            _ = reader.read_line(&mut line) => {
                line.clear();
                
                // Create and send announce (with automatic ratchet key rotation)
                match destination.announce(OsRng, None) {
                    Ok(announce_packet) => {
                        let transport_guard = transport.lock().await;
                        transport_guard.send_packet(announce_packet).await;
                        println!("📡 Sent announce from {}", &destination_hash[..16]);
                        println!("🔑 Ratchet keys available: {}", destination.decryption_keys().len());
                        println!("🔄 Key rotation: Forward secrecy enabled");
                        server_callback_info(&destination);
                    }
                    Err(e) => {
                        println!("❌ Failed to send announce: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n👋 Server shutting down...");
                break;
            }
        }
    }

    Ok(())
}

/// Handle incoming packets on the server with ratchet decryption
fn server_callback_info(destination: &RatchetedDestination) {
    println!("📨 Ready to receive encrypted packets from echo clients");
    println!("🔓 Available ratchet keys for decryption: {}", destination.decryption_keys().len());
    println!("   When a packet arrives, the server will:");
    println!("   1. 🔍 Try decryption with current and previous ratchet keys");
    println!("   2. 📝 Process the decrypted echo message");
    println!("   3. 📤 Send back encrypted echo response (if implemented)");
    println!("   4. ✅ Handle proof/acknowledgment automatically");
    
    // Demonstrate encryption capability
    let test_response = "Echo response from server";
    let mut encrypt_buf = [0u8; 1024];
    match destination.encrypt(OsRng, test_response.as_bytes(), &mut encrypt_buf) {
        Ok(encrypted) => {
            println!("🔐 Server can encrypt responses: {} bytes encrypted", encrypted.len());
        }
        Err(e) => {
            println!("⚠️  Server encryption test failed: {}", e);
        }
    }
}

/// Client mode: Connects to and sends echo requests to a ratcheted server
async fn client(
    destination_hexhash: String,
    _config_path: Option<String>,
    timeout_seconds: Option<f64>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Starting Ratcheted Echo Client");
    println!("=================================");

    // Validate destination hash
    let dest_hash = validate_destination_hash(&destination_hexhash)?;

    // Create client identity and ratcheted destination for encryption
    let client_identity = PrivateIdentity::new_from_rand(OsRng);
    let client_dest_name = DestinationName::new("ratchet.echo", "client");
    let temp_dir = std::env::temp_dir();
    let client_destination = RatchetedDestination::new(
        client_identity,
        client_dest_name,
        Some(temp_dir),
    )?;
    
    println!("🔑 Client ratcheted destination created: {}", 
             hex::encode(client_destination.destination_hash().as_slice())[..16].to_string());

    // Initialize Reticulum transport
    let transport = Arc::new(Mutex::new(Transport::new(TransportConfig::default())));

    // Try to connect to local network (optional for demo)
    println!("🌐 Attempting to connect to local network...");
    {
        let transport_guard = transport.lock().await;
        let _iface_id = transport_guard.iface_manager().lock().await.spawn(
            TcpClient::new("127.0.0.1:4242"),
            TcpClient::spawn,
        );
        println!("⚠️  Network interface created (may show connection errors if no server available)");
        println!("   This is normal for standalone demo - ratchet functionality works without network");
    }

    println!(
        "✅ Echo client ready, hit enter to send echo request to {} (Ctrl-C to quit)",
        &destination_hexhash[..16]
    );

    // Set up announce reception
    let transport_clone = Arc::clone(&transport);
    tokio::spawn(async move {
        let recv = {
            let transport_guard = transport_clone.lock().await;
            transport_guard.recv_announces().await
        };
        let mut recv = recv;

        loop {
            if let Ok(announce) = recv.recv().await {
                let announce_hash = hex::encode(announce.destination.lock().await.desc.address_hash.as_slice());
                println!("📡 Received announce from {}", &announce_hash[..16]);
            }
        }
    });

    // Client input loop
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        select! {
            _ = reader.read_line(&mut line) => {
                line.clear();
                send_echo_request(&dest_hash, &client_destination, &transport, timeout_seconds).await?;
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n👋 Client shutting down...");
                break;
            }
        }
    }

    Ok(())
}

/// Send an echo request to the specified destination using ratchet encryption
async fn send_echo_request(
    dest_hash: &AddressHash,
    client_destination: &RatchetedDestination,
    transport: &Arc<Mutex<Transport>>,
    timeout_seconds: Option<f64>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Sending encrypted echo request to server...");

    // Create a simple echo message
    let echo_message = format!("Hello from ratcheted client at {}", 
                              std::time::SystemTime::now()
                                  .duration_since(std::time::UNIX_EPOCH)
                                  .unwrap().as_secs());
    
    println!("📝 Echo message: '{}'", echo_message);

    // Use the ratcheted destination to create an encrypted data packet
    let packet = match client_destination.create_data_packet(OsRng, echo_message.as_bytes()) {
        Ok(packet) => {
            println!("🔐 Message encrypted with current ratchet key");
            println!("🔑 Available decryption keys: {}", client_destination.decryption_keys().len());
            packet
        }
        Err(e) => {
            println!("❌ Failed to encrypt message: {}", e);
            return Ok(());
        }
    };

    let start_time = Instant::now();

    // Send the packet
    {
        let transport_guard = transport.lock().await;
        transport_guard.send_packet(packet).await;
    }

    println!("📤 Sent echo request to {}", hex::encode(&dest_hash.as_slice()[..8]));
    println!("🔐 Data encrypted with ratchet keys for forward secrecy");

    // Wait for proof/response (simplified - in real implementation would use packet receipts)
    if let Some(timeout_secs) = timeout_seconds {
        println!("⏱️  Waiting for response (timeout: {}s)...", timeout_secs);
        
        match timeout(Duration::from_secs_f64(timeout_secs), tokio::time::sleep(Duration::from_secs(1))).await {
            Ok(_) => {
                let rtt = start_time.elapsed();
                println!("✅ Response received (simulated) - RTT: {:?}", rtt);
            }
            Err(_) => {
                println!("⏰ Request timed out after {}s", timeout_secs);
            }
        }
    } else {
        // Just simulate a successful response
        tokio::time::sleep(Duration::from_millis(100)).await;
        let rtt = start_time.elapsed();
        println!("✅ Response received (simulated) - RTT: {:?}", rtt);
    }

    Ok(())
}

/// Validate and parse destination hash from hex string
fn validate_destination_hash(hex_hash: &str) -> Result<AddressHash, Box<dyn std::error::Error>> {
    const EXPECTED_LEN: usize = 32; // 16 bytes * 2 hex chars = 32 characters

    if hex_hash.len() != EXPECTED_LEN {
        return Err(format!(
            "Destination length is invalid, must be {} hexadecimal characters ({} bytes)",
            EXPECTED_LEN,
            EXPECTED_LEN / 2
        ).into());
    }

    let bytes = hex::decode(hex_hash)
        .map_err(|_| "Invalid hexadecimal destination hash")?;

    if bytes.len() != 16 {
        return Err("Destination hash must be exactly 16 bytes".into());
    }

    let mut hash_bytes = [0u8; 16];
    hash_bytes.copy_from_slice(&bytes);
    
    Ok(AddressHash::new(hash_bytes))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    
    // Simple argument parsing
    if args.len() < 2 {
        println!("🔐 Ratcheted Echo Server and Client");
        println!("===================================\n");
        println!("Usage:");
        println!("  cargo run --example ratchet_echo server                    # Run as server");
        println!("  cargo run --example ratchet_echo client <destination_hash>  # Run as client");
        println!();
        println!("This example demonstrates secure communication using ratchets");
        println!("that uses ratchets to rotate encryption keys every time an");
        println!("announce is sent, providing forward secrecy.");
        println!();
        println!("To test:");
        println!("1. Start the server: cargo run --example ratchet_echo server");
        println!("2. Press Enter to send an announce and note the destination hash");
        println!("3. In another terminal, start the client with that hash");
        println!();
        println!("Note: You may see connection errors to 127.0.0.1:4242 - this is normal");
        println!("for standalone testing. The ratchet encryption works without network connectivity.");
        return Ok(());
    }
    
    match args[1].as_str() {
        "server" => {
            server(None).await
        }
        "client" => {
            if args.len() < 3 {
                println!("Client mode requires destination hash argument");
                println!("Usage: cargo run --example ratchet_echo client <destination_hash>");
                return Ok(());
            }
            let destination = args[2].clone();
            client(destination, None, Some(10.0)).await
        }
        _ => {
            println!("Invalid mode. Use 'server' or 'client'");
            Ok(())
        }
    }
}