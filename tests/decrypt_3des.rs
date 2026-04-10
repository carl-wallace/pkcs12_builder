//! Uses test data from PR2280 from RustCrypto/formats
#![cfg(feature = "legacy")]

use pkcs12_builder::get_key_and_cert;

#[test]
fn decrypt_3des() {
    let p12_iter1 = include_bytes!("data/test-3des-iter1.p12");
    let p12_iter2048 = include_bytes!("data/test-3des-iter2048.p12");
    let p12_iter100000 = include_bytes!("data/test-3des-iter100000.p12");
    let password = "hunter2";
    let contents1 = get_key_and_cert(p12_iter1, password).unwrap();
    let contents2048 = get_key_and_cert(p12_iter2048, password).unwrap();
    let contents100000 = get_key_and_cert(p12_iter100000, password).unwrap();
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
}
