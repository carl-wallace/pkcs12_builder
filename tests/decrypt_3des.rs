//! Uses test data from PR2280 from RustCrypto/formats
#![cfg(feature = "legacy")]

use pkcs12_builder::get_key_and_cert;
use sha2::{Digest, Sha256};

#[test]
fn decrypt_3des() {
    let p12_iter1 = include_bytes!("data/test-3des-iter1.p12");
    let p12_iter2048 = include_bytes!("data/test-3des-iter2048.p12");
    let p12_iter100000 = include_bytes!("data/test-3des-iter100000.p12");
    let password = "hunter2";
    let contents1 = get_key_and_cert(p12_iter1, password).unwrap();
    let contents2048 = get_key_and_cert(p12_iter2048, password).unwrap();
    let contents100000 = get_key_and_cert(p12_iter100000, password).unwrap();
    let rsa_key_der_sha256 =
        hex_literal::hex!("ccdf40f8d0881c5aa3cb9c563399f5fb590f7615ef7da4d057031bc809c9190d");
    let rsa_digest = Sha256::digest(contents1.key_der.clone());
    assert_eq!(rsa_digest.as_slice(), rsa_key_der_sha256);
    assert_eq!(contents1.key_id, contents2048.key_id);
    assert_eq!(contents1.key_der, contents2048.key_der);
    assert_eq!(contents1.certificate, contents2048.certificate);
    assert_eq!(contents1.key_id, contents2048.key_id);
    assert_eq!(
        contents1.additional_certificates,
        contents2048.additional_certificates
    );
    assert_eq!(contents1.key_id, contents100000.key_id);
    assert_eq!(contents1.key_der, contents100000.key_der);
    assert_eq!(contents1.certificate, contents100000.certificate);
    assert_eq!(contents1.key_id, contents100000.key_id);
    assert_eq!(
        contents1.additional_certificates,
        contents100000.additional_certificates
    );

    let p12_pyca = include_bytes!("data/pyca-cert-rc2-key-3des.p12");
    let contents_pyca = get_key_and_cert(p12_pyca, "cryptography").unwrap();
    let pyca_ec_key_der_sha256 =
        hex_literal::hex!("956890dd43249260db8b4a7edf87541070086c186f6a5e39e2eba2eec28f634c");
    let ec_digest = Sha256::digest(contents_pyca.key_der.clone());
    assert_eq!(ec_digest.as_slice(), pyca_ec_key_der_sha256);
}
