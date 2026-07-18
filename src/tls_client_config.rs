use anyhow::bail;
use rustls::{ClientConfig, RootCertStore};
use std::fs;
use std::io::{Cursor, Read};

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
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(config)
}
