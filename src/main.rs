mod command_arguments;
mod tls_client_config;
mod tls_server_config;

use crate::command_arguments::CommandArguments;
use anyhow::{anyhow, bail};
use clap::Parser;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{self, split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

#[derive(Clone)]
struct TlsConfigs {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
}

fn load_tls_configs(args: &CommandArguments) -> anyhow::Result<TlsConfigs> {
    let server = tls_server_config::server_config(&args.certificate, &args.private_key)?;
    let client = tls_client_config::client_config(&args.root_ca)?;
    Ok(TlsConfigs {
        server: Arc::new(server),
        client: Arc::new(client),
    })
}

// References:
// https://postgresconf.org/system/events/document/000/000/183/pgconf_us_v4.pdf
// https://www.tzeejay.com/blog/2022/06/golang-postgresql-check-certificates
// https://www.postgresql.org/docs/current/ssl-tcp.html
// https://www.postgresql.org/docs/current/libpq-ssl.html
// https://xnuter.medium.com/writing-a-modern-http-s-tunnel-in-rust-56e70d898700
// https://ocw.mit.edu/courses/6-875-cryptography-and-cryptanalysis-spring-2005/
// https://tailscale.com/blog/introducing-pgproxy
// AWS - Aurora / RDS: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
// Google - Cloud SQL: https://github.com/brianc/node-postgres-docs/issues/79#issuecomment-1553759056

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: CommandArguments = CommandArguments::parse();

    let initial_tls_configs = load_tls_configs(&args)?;
    let (tls_configs_tx, tls_configs_rx) = watch::channel(initial_tls_configs);

    spawn_reload_on_sighup(args.clone(), tls_configs_tx)?;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", &args.server_port)).await?;
    eprintln!("pgrelay: listening on 0.0.0.0:{}", &args.server_port);
    while let Ok((inbound_tcp_stream, peer_addr)) = listener.accept().await {
        let tls_configs = tls_configs_rx.borrow().clone();
        let client_host = args.client_host.to_owned();
        let client_port = args.client_port.to_owned();
        tokio::spawn(async move {
            if let Err(err) =
                handle_inbound_request(inbound_tcp_stream, tls_configs, client_host, client_port)
                    .await
            {
                eprintln!("pgrelay: connection from {peer_addr} failed: {err:#}");
            }
        });
    }

    bail!("Something went wrong with the listener! Exiting program.")
}

// SIGHUP is intercepted here so it triggers a certificate/root-CA reload
// instead of the default action (terminate the process). A failed reload is
// logged and the previous, still-valid configuration keeps serving.
#[cfg(unix)]
fn spawn_reload_on_sighup(
    args: CommandArguments,
    tls_configs_tx: watch::Sender<TlsConfigs>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sighup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        loop {
            if sighup.recv().await.is_none() {
                break;
            }
            match load_tls_configs(&args) {
                Ok(new_configs) => {
                    let _ = tls_configs_tx.send(new_configs);
                    eprintln!("pgrelay: SIGHUP received, certificates reloaded");
                }
                Err(err) => {
                    eprintln!(
                        "pgrelay: SIGHUP received, reload failed, keeping previous certificates: {err:#}"
                    );
                }
            }
        }
    });

    Ok(())
}

#[cfg(not(unix))]
fn spawn_reload_on_sighup(
    _args: CommandArguments,
    _tls_configs_tx: watch::Sender<TlsConfigs>,
) -> anyhow::Result<()> {
    Ok(())
}

async fn handle_inbound_request(
    inbound_stream: TcpStream,
    tls_configs: TlsConfigs,
    connection_host_or_ip: String,
    connection_port: String,
) -> anyhow::Result<()> {
    let inbound_tls_stream = inbound_handshake(inbound_stream, tls_configs.server).await?;

    let outbound_tls_stream = outbound_handshake(
        &connection_host_or_ip,
        &connection_port,
        tls_configs.client,
    )
    .await?;

    join(inbound_tls_stream, outbound_tls_stream).await?;

    Ok(())
}

async fn inbound_handshake(
    mut inbound_stream: TcpStream,
    server_config: Arc<ServerConfig>,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let mut buffer = [0u8; 8];
    inbound_stream.read_exact(&mut buffer).await?;
    if !buffer.starts_with(&[0, 0, 0, 8, 4, 210, 22, 47]) {
        // tell pgClient we do not support plaintext connections
        inbound_stream.write_all(b"N").await?;
        bail!("TLS not supported by PG client on inbound connection");
    }
    // tell pgClient we're proceeding with TLS
    inbound_stream.write_all(b"S").await?;

    let stream = TlsAcceptor::from(server_config)
        .accept(inbound_stream)
        .await?
        .into();

    Ok(stream)
}

async fn outbound_handshake(
    connection_host_or_ip: &str,
    connection_port: &str,
    client_config: Arc<ClientConfig>,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let connect_to = format!("{}:{}", connection_host_or_ip, connection_port);
    let connect_to = connect_to
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow!("Invalid address: {connect_to:?}"))?;
    let mut outbound_stream = TcpStream::connect(connect_to).await?;
    // tell pgServer we only support TLS connections
    outbound_stream
        .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
        .await?;
    let mut buffer = [0u8; 1];
    outbound_stream.read_exact(&mut buffer).await?;
    if !buffer.starts_with(b"S") {
        bail!("TLS not supported by PG server on outbound connection");
    }

    // The hostname carried here is never checked (see ChainOnlyVerifier in
    // tls_client_config.rs) — only chain-of-trust is verified — so any valid
    // ServerName satisfies the TlsConnector::connect API.
    let stream = TlsConnector::from(client_config)
        .connect(
            ServerName::try_from(connection_host_or_ip.to_owned())?,
            outbound_stream,
        )
        .await?
        .into();

    Ok(stream)
}

async fn join(
    inbound: TlsStream<TcpStream>,
    outbound: TlsStream<TcpStream>,
) -> anyhow::Result<()> {
    let (mut ir, mut iw) = split(inbound);
    let (mut or, mut ow) = split(outbound);

    tokio::try_join!(io::copy(&mut ir, &mut ow), io::copy(&mut or, &mut iw))?;

    Ok(())
}
