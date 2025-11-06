use std::{env, path::PathBuf, time::Duration};

use rand_core::OsRng;
use reticulum::destination::{DestinationName, RatchetedDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};
use tokio::io::{self, AsyncBufReadExt};

const APP_NAME: &str = "example_utilities";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let mode = &args[1];

    match mode.as_str() {
        "server" | "-s" => {
            server().await?;
        }
        "client" | "-c" => {
            if args.len() < 3 {
                println!("Client mode requires destination hash argument");
                print_usage();
                return Ok(());
            }
            let destination_hash = &args[2];
            client(destination_hash).await?;
        }
        _ => {
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Usage:");
    println!("  cargo run --example ratchet_echo server    # Run as server");
    println!("  cargo run --example ratchet_echo client <destination_hash>  # Run as client");
    println!();
    println!("This example demonstrates a simple client/server echo utility");
    println!("that uses ratchets to rotate encryption keys every time an");
    println!("announce is sent, providing forward secrecy.");
}

/// Server implementation - creates a ratcheted destination and waits for client requests
async fn server() -> Result<(), Box<dyn std::error::Error>> {
    println!("##########################################################");
    println!("# Reticulum Ratcheted Echo Server                       #");
    println!("##########################################################");

    // Initialize transport
    let transport = Transport::new(TransportConfig::default());

    // Create TCP client interface (connecting to a Reticulum node)
    let _client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    // Create server identity
    let server_identity = PrivateIdentity::new_from_rand(OsRng);

    // Create ratcheted destination
    let destination = RatchetedDestination::new(
        server_identity,
        DestinationName::new(APP_NAME, "ratchet.echo.request"),
    );

    // Enable ratchets with a temporary file for this example
    // In real-world applications, this file path should be secure and persistent
    let destination_hex = hex::encode(destination.destination_hash().as_slice());
    let ratchet_file = PathBuf::from(format!("/tmp/{}.ratchets", destination_hex));

    destination.enable_ratchets(OsRng, ratchet_file)?;

    println!(
        "Ratcheted echo server {} running",
        hex::encode(destination.destination_hash().as_slice())
    );
    println!("Ratchets enabled: {}", destination.ratchets_enabled());
    println!("Hit enter to manually send an announce (Ctrl-C to quit)");

    // Wait a moment for interface to initialize
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send initial announce
    let announce_packet = destination.announce(OsRng, None)?;
    transport.send_broadcast(announce_packet, None).await;
    println!(
        "Sent announce from {}",
        hex::encode(destination.destination_hash().as_slice())
    );

    // Setup stdin reader for manual announces
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin);
    let mut line = String::new();

    loop {
        tokio::select! {
            // Handle user input for manual announces
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        // Send announce with key rotation
                        let announce_packet = destination.announce(OsRng, None)?;
                        transport.send_broadcast(announce_packet, None).await;
                        println!("Sent announce from {}",
                                hex::encode(destination.destination_hash().as_slice()));
                        line.clear();
                    }
                    Err(e) => {
                        eprintln!("Error reading input: {}", e);
                        break;
                    }
                }
            }

            // Add a small delay to prevent busy waiting
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    Ok(())
}

/// Client implementation - connects to server and sends echo requests
async fn client(destination_hexhash: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("##########################################################");
    println!("# Reticulum Ratcheted Echo Client                       #");
    println!("##########################################################");

    // Validate destination hash
    if destination_hexhash.len() != 32 {
        return Err(
            "Destination length is invalid, must be 32 hexadecimal characters (16 bytes)".into(),
        );
    }

    let destination_hash = hex::decode(destination_hexhash)
        .map_err(|_| "Invalid destination entered. Check your input!")?;

    if destination_hash.len() != 16 {
        return Err("Invalid destination hash length".into());
    }

    // Initialize transport
    let transport = Transport::new(TransportConfig::default());

    // Create TCP client interface
    let _client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    println!(
        "Echo client ready, hit enter to send echo request to {} (Ctrl-C to quit)",
        destination_hexhash
    );

    // Wait for interface to initialize
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Setup stdin reader
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin);
    let mut line = String::new();

    loop {
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Create a simple echo request
                let _echo_data = b"Hello from ratcheted client!";
                println!("Sending echo request...");

                // In a real implementation, you would:
                // 1. Check if we have a path to the destination
                // 2. Create an outgoing destination with the server's identity
                // 3. Encrypt the data using ratchet keys if available
                // 4. Send the packet and wait for proof

                println!("Echo request sent (this is a simplified example)");
                println!("In a full implementation, this would encrypt data with ratchet keys");

                line.clear();
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ratchet_destination_creation() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let destination =
            RatchetedDestination::new(identity, DestinationName::new("test", "ratchet"));

        // Initially ratchets should be disabled
        assert!(!destination.ratchets_enabled());

        // Should be able to get destination hash
        let _hash = destination.destination_hash();
    }

    #[tokio::test]
    async fn test_ratchet_enabling() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let destination =
            RatchetedDestination::new(identity, DestinationName::new("test", "ratchet"));

        let temp_file = std::env::temp_dir().join("test_ratchet.json");

        // Enable ratchets
        destination
            .enable_ratchets(OsRng, temp_file.clone())
            .unwrap();

        // Now ratchets should be enabled
        assert!(destination.ratchets_enabled());

        // Should have current encryption key
        assert!(destination.current_encryption_key().is_some());

        // Clean up
        let _ = std::fs::remove_file(temp_file);
    }

    #[tokio::test]
    async fn test_key_rotation_on_announce() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let destination =
            RatchetedDestination::new(identity, DestinationName::new("test", "ratchet"));

        let temp_file = std::env::temp_dir().join("test_ratchet_announce.json");

        // Enable ratchets
        destination
            .enable_ratchets(OsRng, temp_file.clone())
            .unwrap();

        // Get initial key
        let initial_key = destination.current_encryption_key().unwrap();

        // Send announce (should rotate key)
        let _announce1 = destination.announce(OsRng, None).unwrap();

        // Key should have changed
        let new_key = destination.current_encryption_key().unwrap();
        assert_ne!(initial_key.as_bytes(), new_key.as_bytes());

        // Send another announce
        let _announce2 = destination.announce(OsRng, None).unwrap();

        // Key should have changed again
        let newer_key = destination.current_encryption_key().unwrap();
        assert_ne!(new_key.as_bytes(), newer_key.as_bytes());

        // Should have multiple decryption keys available
        let decryption_keys = destination.decryption_keys();
        assert!(decryption_keys.len() > 1);

        // Clean up
        let _ = std::fs::remove_file(temp_file);
    }
}
