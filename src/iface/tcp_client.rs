use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use tokio::io::AsyncReadExt;

use alloc::string::String;

use super::hdlc::Hdlc;
use super::{Interface, InterfaceContext};

// TODO: Configure via features
const PACKET_TRACE: bool = false;

pub struct TcpClient {
    addr: String,
    stream: Option<TcpStream>,
}

impl TcpClient {
    pub fn new<T: Into<String>>(addr: T) -> Self {
        Self {
            addr: addr.into(),
            stream: None,
        }
    }

    pub fn new_from_stream<T: Into<String>>(addr: T, stream: TcpStream) -> Self {
        Self {
            addr: addr.into(),
            stream: Some(stream),
        }
    }

    pub async fn spawn(context: InterfaceContext<TcpClient>) {
        let iface_stop = context.channel.stop.clone();
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let iface_address = context.channel.address;
        let mut stream = { context.inner.lock().unwrap().stream.take() };

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        let mut running = true;
        loop {
            if !running || context.cancel.is_cancelled() {
                break;
            }

            let stream = {
                match stream.take() {
                    Some(stream) => {
                        running = false;
                        Ok(stream)
                    }
                    None => TcpStream::connect(addr.clone())
                        .await
                        .map_err(|_| RnsError::ConnectionError),
                }
            };

            if let Err(_) = stream {
                log::info!("tcp_client: couldn't connect to <{}>", addr);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let stream = stream.unwrap();
            let (read_stream, write_stream) = stream.into_split();

            log::info!("tcp_client connected to <{}>", addr);

            const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 2;

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let mut stream = read_stream;
                let rx_channel = rx_channel.clone();

                tokio::spawn(async move {
                    let mut hdlc_rx_buffer = [0u8; BUFFER_SIZE];
                    let mut rx_buffer = [0u8; BUFFER_SIZE + (BUFFER_SIZE / 2)];
                    let mut rx_write_pos = 0usize;  // Track write position in rx_buffer
                    let mut tcp_buffer = [0u8; (BUFFER_SIZE * 16)];

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            result = stream.read(&mut tcp_buffer[..]) => {
                                    match result {
                                        Ok(0) => {
                                            log::warn!("tcp_client: connection closed");
                                            stop.cancel();
                                            break;
                                        }
                                        Ok(n) => {
                                            log::trace!("tcp_client: read {} bytes from TCP stream", n);
                                            
                                            // Append incoming data to rx_buffer
                                            for i in 0..n {
                                                if rx_write_pos >= rx_buffer.len() {
                                                    // Buffer full, shift data and make room
                                                    log::warn!("tcp_client: rx_buffer full, shifting data");
                                                    let half_len = rx_buffer.len() / 2;
                                                    rx_buffer.copy_within(half_len.., 0);
                                                    rx_write_pos = half_len;
                                                }
                                                rx_buffer[rx_write_pos] = tcp_buffer[i];
                                                rx_write_pos += 1;
                                            }

                                            // Process all complete HDLC frames in buffer
                                            loop {
                                                let frame = Hdlc::find(&rx_buffer[..rx_write_pos]);
                                                if let Some(frame) = frame {
                                                    let frame_start = frame.0;
                                                    let frame_end = frame.1;
                                                    
                                                    // Decode HDLC frame and deserialize packet
                                                    let frame_buffer = &mut rx_buffer[frame_start..frame_end+1];
                                                    let mut output = OutputBuffer::new(&mut hdlc_rx_buffer[..]);
                                                    if let Ok(_) = Hdlc::decode(frame_buffer, &mut output) {
                                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(output.as_slice())) {
                                                            log::debug!(
                                                                "tcp_client: rx << ({}) context={:?} dest={} type={:?}",
                                                                iface_address,
                                                                packet.context,
                                                                packet.destination,
                                                                packet.header.packet_type
                                                            );
                                                            if PACKET_TRACE {
                                                                log::trace!("tcp_client: rx << ({}) {}", iface_address, packet);
                                                            }
                                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                        } else {
                                                            log::warn!("tcp_client: couldn't decode packet");
                                                        }
                                                    } else {
                                                        log::warn!("tcp_client: couldn't decode hdlc frame");
                                                    }

                                                    // Remove processed frame from buffer by shifting remaining data
                                                    let remaining = rx_write_pos - (frame_end + 1);
                                                    if remaining > 0 {
                                                        rx_buffer.copy_within(frame_end+1..rx_write_pos, 0);
                                                    }
                                                    rx_write_pos = remaining;
                                                } else {
                                                    // No complete frame found, wait for more data
                                                    break;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!("tcp_client: connection error {}", e);
                                            break;
                                        }
                                    }
                                },
                        };
                    }
                })
            };

            // Start transmit task
            let tx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();  // Clone stop for TX task
                let tx_channel = tx_channel.clone();
                let mut stream = write_stream;

                tokio::spawn(async move {
                    loop {
                        if stop.is_cancelled() {
                            break;
                        }

                        let mut hdlc_tx_buffer = [0u8; BUFFER_SIZE];
                        let mut tx_buffer = [0u8; BUFFER_SIZE];

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            Some(message) = tx_channel.recv() => {
                                let packet = message.packet;
                                log::debug!(
                                    "tcp_client: tx >> ({}) context={:?} dest={} type={:?}",
                                    iface_address,
                                    packet.context,
                                    packet.destination,
                                    packet.header.packet_type
                                );
                                if PACKET_TRACE {
                                    log::trace!("tcp_client: tx >> ({}) {}", iface_address, packet);
                                }
                                let mut output = OutputBuffer::new(&mut tx_buffer);
                                if let Ok(_) = packet.serialize(&mut output) {

                                    let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);

                                    if let Ok(_) = Hdlc::encode(output.as_slice(), &mut hdlc_output) {
                                        match stream.write_all(hdlc_output.as_slice()).await {
                                            Ok(_) => {
                                                match stream.flush().await {
                                                    Ok(_) => {
                                                        log::debug!(
                                                            "tcp_client: successfully sent {} bytes to wire",
                                                            hdlc_output.as_slice().len()
                                                        );
                                                    }
                                                    Err(e) => {
                                                        log::error!("tcp_client: flush failed: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                log::error!("tcp_client: write failed: {}", e);
                                            }
                                        }
                                    } else {
                                        log::error!("tcp_client: HDLC encode failed");
                                    }
                                } else {
                                    log::error!("tcp_client: packet serialization failed");
                                }
                            }
                        };
                    }
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            log::info!("tcp_client: disconnected from <{}>", addr);
        }

        iface_stop.cancel();
    }
}

impl Interface for TcpClient {
    fn mtu() -> usize {
        2048
    }
}
