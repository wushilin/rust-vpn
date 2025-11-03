use anyhow::{Context, Result};
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

pub fn load_cert_chain(pem_file: &str) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    debug!("Loading certificate chain from: {}", pem_file);
    let pem_bytes = fs::read(pem_file)
        .with_context(|| format!("Failed to read certificate file: {}", pem_file))?;
    let pem_str = String::from_utf8(pem_bytes)
        .context("Certificate file is not valid UTF-8")?;

    let mut certs = Vec::new();
    for pem in rustls_pemfile::certs(&mut pem_str.as_bytes()) {
        let cert = pem.context("Failed to parse PEM certificate")?;
        certs.push(rustls_pki_types::CertificateDer::from(cert));
    }

    if certs.is_empty() {
        error!("No certificates found in {}", pem_file);
        anyhow::bail!("No certificates found in {}", pem_file);
    }

    info!("Loaded {} certificate(s) from {}", certs.len(), pem_file);
    Ok(certs)
}

pub fn load_private_key(pem_file: &str) -> Result<rustls_pki_types::PrivateKeyDer<'static>> {
    debug!("Loading private key from: {}", pem_file);
    let pem_bytes = fs::read(pem_file)
        .with_context(|| format!("Failed to read key file: {}", pem_file))?;
    let pem_str = String::from_utf8(pem_bytes)
        .context("Key file is not valid UTF-8")?;

    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut pem_str.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM private key")?;

    if keys.is_empty() {
        debug!("No PKCS8 key found, trying RSA format");
        let mut rsa_keys = rustls_pemfile::rsa_private_keys(&mut pem_str.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse PEM RSA private key")?;
        if rsa_keys.is_empty() {
            error!("No private key found in {}", pem_file);
            anyhow::bail!("No private key found in {}", pem_file);
        }
        info!("Loaded RSA private key from {}", pem_file);
        return Ok(rustls_pki_types::PrivateKeyDer::from(
            rustls_pki_types::PrivatePkcs1KeyDer::from(rsa_keys.remove(0))
        ));
    }

    info!("Loaded PKCS8 private key from {}", pem_file);
    Ok(rustls_pki_types::PrivateKeyDer::from(
        rustls_pki_types::PrivatePkcs8KeyDer::from(keys.remove(0))
    ))
}

pub fn load_ca_bundle(pem_file: &str) -> Result<quinn::rustls::RootCertStore> {
    debug!("Loading CA bundle from: {}", pem_file);
    let pem_bytes = fs::read(pem_file)
        .with_context(|| format!("Failed to read CA bundle file: {}", pem_file))?;
    let pem_str = String::from_utf8(pem_bytes)
        .context("CA bundle file is not valid UTF-8")?;

    let mut root_store = quinn::rustls::RootCertStore::empty();
    let mut count = 0;
    for pem in rustls_pemfile::certs(&mut pem_str.as_bytes()) {
        let cert = pem.context("Failed to parse PEM certificate in CA bundle")?;
        root_store.add(cert)
            .context("Failed to add certificate to root store")?;
        count += 1;
    }

    if root_store.is_empty() {
        error!("No CA certificates found in {}", pem_file);
        anyhow::bail!("No CA certificates found in {}", pem_file);
    }

    info!("Loaded {} CA certificate(s) from {}", count, pem_file);
    Ok(root_store)
}

pub fn load_ca_bundle_tcp(pem_file: &str) -> Result<rustls::RootCertStore> {
    debug!("Loading CA bundle from: {}", pem_file);
    let pem_bytes = fs::read(pem_file)
        .with_context(|| format!("Failed to read CA bundle file: {}", pem_file))?;
    let pem_str = String::from_utf8(pem_bytes)
        .context("CA bundle file is not valid UTF-8")?;

    let mut root_store = rustls::RootCertStore::empty();
    let mut count = 0;
    for pem in rustls_pemfile::certs(&mut pem_str.as_bytes()) {
        let cert = pem.context("Failed to parse PEM certificate in CA bundle")?;
        root_store.add(cert)?;
        count += 1;
    }

    if root_store.is_empty() {
        error!("No CA certificates found in {}", pem_file);
        anyhow::bail!("No CA certificates found in {}", pem_file);
    }

    info!("Loaded {} CA certificate(s) from {}", count, pem_file);
    Ok(root_store)
}

pub fn load_ca_bundle_tcp_tokio(pem_file: &str) -> Result<tokio_rustls::rustls::RootCertStore> {
    debug!("Loading CA bundle from: {}", pem_file);
    let pem_bytes = fs::read(pem_file)
        .with_context(|| format!("Failed to read CA bundle file: {}", pem_file))?;
    let pem_str = String::from_utf8(pem_bytes)
        .context("CA bundle file is not valid UTF-8")?;

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    let mut count = 0;
    for pem in rustls_pemfile::certs(&mut pem_str.as_bytes()) {
        let cert = pem.context("Failed to parse PEM certificate in CA bundle")?;
        root_store.add(cert)?;
        count += 1;
    }

    if root_store.is_empty() {
        error!("No CA certificates found in {}", pem_file);
        anyhow::bail!("No CA certificates found in {}", pem_file);
    }

    info!("Loaded {} CA certificate(s) from {}", count, pem_file);
    Ok(root_store)
}

pub fn extract_cn_from_cert(cert: &rustls_pki_types::CertificateDer) -> Result<String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

    let subject = cert.subject();
    for rdn in subject.iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_id_string() == "2.5.4.3" {
                if let Ok(cn) = attr.as_str() {
                    return Ok(cn.to_string());
                }
            }
        }
    }

    anyhow::bail!("CN not found in certificate");
}

/// Extract CN from a quinn connection's peer identity.
/// This should be called after the connection handshake is complete.
/// peer_identity is Box<dyn Any> which for rustls is Vec<rustls_pki_types::CertificateDer>
pub fn extract_cn_from_peer_identity(peer_identity: &Box<dyn std::any::Any>) -> Result<String> {
    // For rustls, peer_identity is Vec<rustls_pki_types::CertificateDer>
    let certs = peer_identity.downcast_ref::<Vec<rustls_pki_types::CertificateDer>>()
        .ok_or_else(|| anyhow::anyhow!("Peer identity is not rustls certificate vector"))?;
    
    if certs.is_empty() {
        anyhow::bail!("No certificates in peer identity");
    }
    
    // Extract CN from the first (end entity) certificate
    extract_cn_from_cert(&certs[0])
}

/// Validate peer CN after connection handshake.
/// Returns an error if CN doesn't match expected value.
pub fn validate_peer_cn(
    connection: &quinn::Connection,
    expected_cn: &str,
) -> Result<()> {
    debug!("Validating peer CN: expected '{}'", expected_cn);
    let peer_identity = connection.peer_identity()
        .ok_or_else(|| anyhow::anyhow!("No peer identity available"))?;
    
    let cn = extract_cn_from_peer_identity(&peer_identity)?;
    if cn != expected_cn {
        error!("CN mismatch: expected '{}', got '{}'", expected_cn, cn);
        anyhow::bail!("CN mismatch: expected '{}', got '{}'", expected_cn, cn);
    }
    
    debug!("Peer CN validation successful: '{}'", cn);
    Ok(())
}

pub fn build_server_config(
    ca_bundle_path: &str,
    server_cert_path: &str,
    server_key_path: &str,
    transport_config: quinn::TransportConfig,
) -> Result<quinn::ServerConfig> {
    let cert_chain = load_cert_chain(server_cert_path)?;
    let key = load_private_key(server_key_path)?;

    // Use rustls's standard WebPkiClientVerifier which validates client certs against the CA store.
    // This is rustls's standard verifier - no custom verification logic, just standard CA validation.
    // Convert quinn's rustls RootCertStore to rustls's RootCertStore
    let mut rustls_ca_store = rustls::RootCertStore::empty();
    // Re-read CA bundle to build rustls RootCertStore (quinn's wrapper doesn't expose iterator)
    let ca_bundle_bytes = fs::read(ca_bundle_path)
        .with_context(|| format!("Failed to read CA bundle file: {}", ca_bundle_path))?;
    let ca_bundle_str = String::from_utf8(ca_bundle_bytes)
        .context("CA bundle file is not valid UTF-8")?;
    for pem in rustls_pemfile::certs(&mut ca_bundle_str.as_bytes()) {
        let cert = pem.context("Failed to parse PEM certificate in CA bundle")?;
        rustls_ca_store.add(cert)?;
    }
    
    // Build rustls ServerConfig directly using rustls's standard WebPkiClientVerifier
    // Then convert to quinn's wrapper. This uses rustls's standard CA-validating verifier.
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(rustls_ca_store.into())
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create client cert verifier: {}", e))?;

    let rustls_server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("Failed to create rustls server config: {}", e))?;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server_config)
        .map_err(|e| anyhow::anyhow!("Failed to create quinn server config: {}", e))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport = Arc::new(transport_config);
    Ok(server_config)
}

pub fn build_client_config(
    ca_bundle_path: &str,
    client_cert_path: &str,
    client_key_path: &str,
    transport_config: quinn::TransportConfig,
) -> Result<quinn::ClientConfig> {
    let ca_store = load_ca_bundle(ca_bundle_path)?;
    let client_cert_chain = load_cert_chain(client_cert_path)?;
    let client_private_key = load_private_key(client_key_path)?;

    // Use rustls's standard CA verification - no custom verifier needed.
    // We'll check CN after connection using peer identity.
    let rustls_config = quinn::rustls::ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(client_cert_chain, client_private_key)
        .map_err(|e| anyhow::anyhow!("Failed to create rustls client config: {}", e))?;

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
}

pub fn get_client_transport_config() -> Result<quinn::TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();
    // Optional datagram buffers for flexibility
    transport_config.datagram_receive_buffer_size(Some(32*1024*1024));
    transport_config.datagram_send_buffer_size(3*1024*1024);
    // High BDP windows to sustain throughput on high-latency links
    transport_config.receive_window(quinn::VarInt::from_u64(128 * 1024 * 1024)?);
    transport_config.send_window(128 * 1024 * 1024);
    transport_config.stream_receive_window(quinn::VarInt::from_u64(32 * 1024 * 1024)?);
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport_config.max_concurrent_bidi_streams(200_u32.into());
    transport_config.max_concurrent_uni_streams(200_u32.into());
    transport_config.max_idle_timeout(Some(Duration::from_secs(5).try_into().map_err(|_| anyhow::anyhow!("invalid idle timeout"))?));
    Ok(transport_config)
}

pub fn get_server_transport_config() -> Result<quinn::TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();
    // Enable datagram buffers for datagram support
    transport_config.datagram_receive_buffer_size(Some(32*1024*1024));
    transport_config.datagram_send_buffer_size(32*1024*1024);
    transport_config.receive_window(quinn::VarInt::from_u64(128 * 1024 * 1024)?);
    transport_config.send_window(128 * 1024 * 1024);
    transport_config.stream_receive_window(quinn::VarInt::from_u64(32 * 1024 * 1024)?);
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport_config.max_concurrent_bidi_streams(200_u32.into());
    transport_config.max_concurrent_uni_streams(200_u32.into());
    transport_config.max_idle_timeout(Some(Duration::from_secs(5).try_into().map_err(|_| anyhow::anyhow!("invalid idle timeout"))?));
    Ok(transport_config)
}
