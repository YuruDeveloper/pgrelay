use anyhow::bail;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use std::fs;
use std::io::{Cursor, Read};
use std::sync::Arc;

// Verifies the certificate chain against the trusted root CAs but skips the
// hostname check, since the name pgClient connects to may not match the name
// on pgServer's certificate.
#[derive(Debug)]
struct ChainOnlyVerifier {
    roots: Arc<RootCertStore>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ChainOnlyVerifier {
    fn new(roots: Arc<RootCertStore>) -> Self {
        let supported_algs = CryptoProvider::get_default()
            .expect("a process-default CryptoProvider should already be installed")
            .signature_verification_algorithms;
        Self {
            roots,
            supported_algs,
        }
    }
}

impl ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported_algs.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

pub(crate) fn client_config(ca_roots_directory: &str) -> anyhow::Result<ClientConfig> {
    let mut root_cert_store = RootCertStore::empty();
    let read_dir = fs::read_dir(ca_roots_directory)?;

    let mut root_ca_count = 0;
    for r in read_dir {
        let dir_entry = r?;
        let path = dir_entry.path();

        if path.is_file() && path.extension().map_or(false, |e| e == "pem" || e == "crt") {
            let mut file = fs::File::open(&path)?;
            let mut pem_data = Vec::new();
            file.read_to_end(&mut pem_data)?;

            let mut reader = Cursor::new(&pem_data);
            let mut found_in_file = false;
            for cert_result in rustls_pemfile::certs(&mut reader) {
                found_in_file = true;
                root_ca_count += 1;
                let cert = cert_result?;
                root_cert_store.add(cert)?;
            }
            if !found_in_file && !pem_data.is_empty() {
                // .crt files may be DER-encoded rather than PEM
                root_ca_count += 1;
                root_cert_store.add(rustls::pki_types::CertificateDer::from(pem_data))?;
            }
        }
    }

    if root_ca_count == 0 {
        bail!("No root certificates found in directory: {ca_roots_directory:?}");
    }

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ChainOnlyVerifier::new(Arc::new(
            root_cert_store,
        ))))
        .with_no_client_auth();

    Ok(config)
}
