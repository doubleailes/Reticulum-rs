use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmp_serde::{from_slice, to_vec};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::time::{self, Duration};

use reticulum::destination::link::{Link, LinkEvent};
use reticulum::destination::{DestinationDesc, DestinationName, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};

const APP_NAME: &str = "example_utilities";
const SERVER_ASPECT: &str = "filetransfer.server";
const SERVER_IDENTITY_TAG: &str = "filetransfer-server";
const CLIENT_IDENTITY_TAG: &str = "filetransfer-client";
const DEFAULT_LISTEN: &str = "0.0.0.0:4242";
const DEFAULT_CONNECT: &str = "127.0.0.1:4242";
const CHUNK_SIZE: usize = 1200;

#[derive(Debug, Serialize, Deserialize)]
enum ClientMessage {
    List,
    Download { name: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileEntry {
    name: String,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
enum ServerMessage {
    FileList { files: Vec<FileEntry> },
    FileChunk {
        name: String,
        offset: u64,
        total: u64,
        data: Vec<u8>,
        is_last: bool,
    },
    Error { message: String },
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    connect: Option<String>,
}

#[derive(Debug)]
enum Mode {
    Server(ServerArgs),
    Client(ClientArgs),
}

#[derive(Debug)]
struct ServerArgs {
    dir: PathBuf,
    listen: String,
}

#[derive(Debug)]
struct ClientArgs {
    destination: AddressHash,
    output: PathBuf,
    filename: Option<String>,
}

type ExampleResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> ExampleResult<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{}", err);
            eprintln!("");
            print_usage(&env::args().next().unwrap_or_else(|| "filetransfer".into()));
            std::process::exit(2);
        }
    };

    let Args { mode, connect } = args;

    match mode {
        Mode::Server(cfg) => run_server(cfg, connect).await?,
        Mode::Client(cfg) => {
            let endpoint = connect.unwrap_or_else(|| DEFAULT_CONNECT.to_string());
            run_client(cfg, endpoint).await?;
        }
    }

    Ok(())
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} --serve <PATH> [--listen addr] [--connect addr]");
    eprintln!("  {program} --destination <HASH> [--file NAME] [--output DIR] [--connect addr]");
    eprintln!("");
    eprintln!("Examples:");
    eprintln!("  {program} --serve ./public --listen 0.0.0.0:4242");
    eprintln!("  {program} --destination 63817f431a629f974f36792331c144a9 --file demo.txt");
}

fn parse_args() -> Result<Args, String> {
    let mut serve_dir: Option<PathBuf> = None;
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut connect: Option<String> = None;
    let mut destination: Option<AddressHash> = None;
    let mut file: Option<String> = None;
    let mut output_dir: Option<PathBuf> = None;

    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--serve" => {
                let value = iter.next().ok_or("--serve requires a directory path")?;
                serve_dir = Some(PathBuf::from(value));
            }
            "--listen" => {
                listen = iter.next().ok_or("--listen requires an address")?;
            }
            "--connect" => {
                connect = Some(iter.next().ok_or("--connect requires an address")?);
            }
            "--destination" => {
                let hex = iter.next().ok_or("--destination requires a hash")?;
                destination = Some(
                    AddressHash::new_from_hex_string(&hex)
                        .map_err(|_| "invalid destination hash supplied".to_string())?,
                );
            }
            "--file" => {
                file = Some(iter.next().ok_or("--file requires a filename")?);
            }
            "--output" => {
                output_dir = Some(PathBuf::from(iter.next().ok_or("--output requires a path")?));
            }
            "-h" | "--help" => {
                print_usage(&env::args().next().unwrap_or_else(|| "filetransfer".into()));
                std::process::exit(0);
            }
            unknown => return Err(format!("Unknown argument: {unknown}")),
        }
    }

    if serve_dir.is_some() && destination.is_some() {
        return Err("Please choose either server or client mode".into());
    }

    if let Some(dir) = serve_dir {
        return Ok(Args {
            mode: Mode::Server(ServerArgs {
                dir,
                listen,
            }),
            connect,
        });
    }

    let destination = destination.ok_or_else(|| "Client mode requires --destination".to_string())?;
    let output = output_dir
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| "Could not resolve working directory".to_string())?;

    let connect = Some(connect.unwrap_or_else(|| DEFAULT_CONNECT.to_string()));

    Ok(Args {
        mode: Mode::Client(ClientArgs {
            destination,
            output,
            filename: file,
        }),
        connect,
    })
}

async fn run_server(args: ServerArgs, connect: Option<String>) -> ExampleResult<()> {
    if !args.dir.is_dir() {
        return Err(format!("{} is not a directory", args.dir.display()).into());
    }

    let identity = PrivateIdentity::new_from_name(SERVER_IDENTITY_TAG);
    let mut config = TransportConfig::new("filetransfer-server", &identity, true);
    config.set_retransmit(true);
    let mut transport = Transport::new(config);

    transport
    .iface_manager()
    .lock()
    .await
    .spawn(TcpServer::new(args.listen.clone(), transport.iface_manager()), TcpServer::spawn);
    if let Some(addr) = connect {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(addr), TcpClient::spawn);
    }

    let destination = transport
        .add_destination(identity, DestinationName::new(APP_NAME, SERVER_ASPECT))
        .await;

    transport.send_announce(&destination, None).await;
    log::info!(
        "Serving files from {} as {}",
        args.dir.display(),
        destination.lock().await.desc.address_hash
    );

    let mut link_events = transport.in_link_events();
    let mut announce_interval = time::interval(Duration::from_secs(45));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("Shutting down server");
                break;
            }
            _ = announce_interval.tick() => {
                transport.send_announce(&destination, None).await;
            }
            event = link_events.recv() => {
                match event {
                    Ok(event_data) => {
                        handle_server_link_event(&transport, &args.dir, event_data).await?;
                    }
                    Err(err) => {
                        log::warn!("Link event error: {err}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_server_link_event(
    transport: &Transport,
    dir: &Path,
    event: reticulum::destination::link::LinkEventData,
) -> ExampleResult<()> {
    match event.event {
        LinkEvent::Activated => {
            log::info!("Link {} established", event.id);
            send_file_list(transport, &event.id, dir).await?;
        }
        LinkEvent::Data(payload) => {
            process_client_message(transport, &event.id, dir, payload.as_slice()).await?;
        }
        LinkEvent::Closed => {
            log::info!("Link {} closed", event.id);
        }
    }

    Ok(())
}

async fn process_client_message(
    transport: &Transport,
    link_id: &AddressHash,
    dir: &Path,
    data: &[u8],
) -> ExampleResult<()> {
    match from_slice::<ClientMessage>(data) {
        Ok(ClientMessage::List) => {
            send_file_list(transport, link_id, dir).await?;
        }
        Ok(ClientMessage::Download { name }) => {
            if !is_safe_filename(&name) {
                send_error(transport, link_id, "Illegal filename request").await?;
                return Ok(());
            }

            let path = dir.join(&name);
            if !path.exists() || !path.is_file() {
                send_error(transport, link_id, "Requested file not found").await?;
                return Ok(());
            }

            let data = fs::read(&path).await?;
            let total = data.len() as u64;
            let mut offset = 0u64;

            for chunk in data.chunks(CHUNK_SIZE) {
                let message = ServerMessage::FileChunk {
                    name: name.clone(),
                    offset,
                    total,
                    data: chunk.to_vec(),
                    is_last: (offset as usize + chunk.len()) >= data.len(),
                };

                send_message_to_link(transport, link_id, &message).await?;
                offset += chunk.len() as u64;
            }

            log::info!("Sent {} ({} bytes)", name, total);
        }
        Err(err) => {
            log::warn!("Failed to decode client message: {err}");
            send_error(transport, link_id, "Malformed message").await?;
        }
    }

    Ok(())
}

async fn send_file_list(
    transport: &Transport,
    link_id: &AddressHash,
    dir: &Path,
) -> ExampleResult<()> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with('.') || !is_safe_filename(name) {
                continue;
            }

            let size = entry.metadata()?.len();
            entries.push(FileEntry {
                name: name.to_string(),
                size,
            });
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let message = ServerMessage::FileList { files: entries };
    send_message_to_link(transport, link_id, &message).await
}

async fn send_error(transport: &Transport, link_id: &AddressHash, message: &str) -> ExampleResult<()> {
    let payload = ServerMessage::Error {
        message: message.to_string(),
    };
    send_message_to_link(transport, link_id, &payload).await
}

async fn send_message_to_link<T: Serialize + ?Sized>(
    transport: &Transport,
    link_id: &AddressHash,
    message: &T,
) -> ExampleResult<()> {
    let encoded = to_vec(message)?;
    if let Some(link) = transport.find_in_link(link_id).await {
        send_packet_over_link(transport, &link, &encoded).await
    } else {
        Err(format!("Link {} no longer exists", link_id).into())
    }
}

async fn send_packet_over_link(
    transport: &Transport,
    link: &Arc<tokio::sync::Mutex<Link>>,
    data: &[u8],
) -> ExampleResult<()> {
    let packet = {
        let link = link.lock().await;
        link
            .data_packet(data)
            .map_err(|err| format!("failed to prepare link packet: {err}"))?
    };

    let _ = transport.send_packet(packet).await;
    Ok(())
}

async fn run_client(args: ClientArgs, connect: String) -> ExampleResult<()> {
    let identity = PrivateIdentity::new_from_name(CLIENT_IDENTITY_TAG);
    let transport = Transport::new(TransportConfig::new("filetransfer-client", &identity, false));

    transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new(connect), TcpClient::spawn);

    wait_for_path(&transport, &args.destination).await;
    let desc = wait_for_destination_desc(&transport, &args.destination).await;
    let link = transport.link(desc).await;
    let link_id = *link.lock().await.id();

    let mut events = transport.out_link_events();
    let mut download_state = DownloadState::new(args.filename.clone());

    log::info!("Awaiting file list from {}", args.destination);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("Interrupted");
                break;
            }
            event = events.recv() => {
                match event {
                    Ok(event_data) if event_data.id == link_id => {
                        if handle_client_event(&transport, &link, &mut download_state, &args, event_data.event).await? {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        log::warn!("Link event error: {err}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_client_event(
    transport: &Transport,
    link: &Arc<tokio::sync::Mutex<Link>>,
    state: &mut DownloadState,
    args: &ClientArgs,
    event: LinkEvent,
) -> ExampleResult<bool> {
    match event {
        LinkEvent::Activated => {
            log::info!("Link active");
            request_list(transport, link).await?;
        }
        LinkEvent::Data(payload) => {
            let message: ServerMessage = from_slice(payload.as_slice())?;
            match message {
                ServerMessage::FileList { files } => {
                    print_file_list(&files);
                    if let Some(request) = state.pending_request.clone() {
                        if files.iter().any(|entry| entry.name == request) {
                            request_file(transport, link, &request).await?;
                            state.mark_request_sent(&request);
                        } else {
                            log::warn!("Requested file not present on server");
                            return Ok(true);
                        }
                    } else {
                        return Ok(true);
                    }
                }
                ServerMessage::FileChunk { name, offset: _, total, data, is_last } => {
                    state.ensure_target(&name);
                    state.append(&data, total);

                    if is_last {
                        save_download(args, state).await?;
                        return Ok(true);
                    }
                }
                ServerMessage::Error { message } => {
                    log::error!("Server reported error: {message}");
                    return Ok(true);
                }
            }
        }
        LinkEvent::Closed => {
            log::info!("Link closed by server");
            return Ok(true);
        }
    }

    Ok(false)
}

async fn request_file(
    transport: &Transport,
    link: &Arc<tokio::sync::Mutex<Link>>,
    name: &str,
) -> ExampleResult<()> {
    if !is_safe_filename(name) {
        return Err("Refusing to request unsafe filename".into());
    }

    let payload = ClientMessage::Download {
        name: name.to_string(),
    };

    let encoded = to_vec(&payload)?;
    send_packet_over_link(transport, link, &encoded).await?;
    log::info!("Requested {}", name);
    Ok(())
}

async fn request_list(
    transport: &Transport,
    link: &Arc<tokio::sync::Mutex<Link>>,
) -> ExampleResult<()> {
    let payload = to_vec(&ClientMessage::List)?;
    send_packet_over_link(transport, link, &payload).await?;
    log::info!("Requested file list");
    Ok(())
}

async fn save_download(args: &ClientArgs, state: &mut DownloadState) -> ExampleResult<()> {
    let name = state
        .target
        .as_ref()
        .cloned()
        .ok_or("No active download to save")?;

    fs::create_dir_all(&args.output).await?;
    let mut path = args.output.clone();
    path.push(&name);

    fs::write(&path, &state.buffer).await?;
    log::info!(
        "Saved {} ({} bytes) to {}",
        name,
        state.buffer.len(),
        path.display()
    );

    state.reset();

    Ok(())
}

fn print_file_list(files: &[FileEntry]) {
    if files.is_empty() {
        println!("Server reports no downloadable files");
        return;
    }

    println!("Available files:");
    for (idx, entry) in files.iter().enumerate() {
        println!("  {:02}. {:<30} {:>8} bytes", idx + 1, entry.name, entry.size);
    }
}

async fn wait_for_path(transport: &Transport, destination: &AddressHash) {
    let mut attempts = 0;
    loop {
        if transport.has_path(destination).await {
            break;
        }

        if attempts % 3 == 0 {
            transport.request_path(destination, None).await;
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
        attempts += 1;
    }
}

async fn wait_for_destination_desc(
    transport: &Transport,
    destination: &AddressHash,
) -> DestinationDesc {
    loop {
        if let Some(identity) = transport.recall_identity(destination, false).await {
            let output = SingleOutputDestination::new(
                identity,
                DestinationName::new(APP_NAME, SERVER_ASPECT),
            );
            return output.desc;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn is_safe_filename(name: &str) -> bool {
    !(name.is_empty() || name.contains('/') || name.contains('\\') || name.contains(".."))
}

struct DownloadState {
    pending_request: Option<String>,
    target: Option<String>,
    buffer: Vec<u8>,
    expected_total: Option<u64>,
}

impl DownloadState {
    fn new(request: Option<String>) -> Self {
        Self {
            pending_request: request,
            target: None,
            buffer: Vec::new(),
            expected_total: None,
        }
    }

    fn mark_request_sent(&mut self, name: &str) {
        self.pending_request = None;
        self.begin_transfer(name.to_string());
    }

    fn begin_transfer(&mut self, name: String) {
        self.target = Some(name);
        self.buffer.clear();
        self.expected_total = None;
    }

    fn ensure_target(&mut self, name: &str) {
        if self.target.as_deref() != Some(name) {
            self.begin_transfer(name.to_string());
        }
    }

    fn append(&mut self, chunk: &[u8], total: u64) {
        if self.expected_total.is_none() {
            self.expected_total = Some(total);
        }
        self.buffer.extend_from_slice(chunk);
    }

    fn reset(&mut self) {
        self.target = None;
        self.buffer.clear();
        self.expected_total = None;
    }
}
