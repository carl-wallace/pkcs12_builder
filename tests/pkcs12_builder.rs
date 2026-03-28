use pkcs5::{
    pbes2,
    pbes2::{AES_256_CBC_OID, PBES2_OID, PBKDF2_OID, Pbkdf2Params, Pbkdf2Prf},
};
use pkcs8::{
    EncryptedPrivateKeyInfo,
    spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned},
};

use cms::encrypted_data::EncryptedData;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use der::{
    Any, AnyRef, Decode, Encode,
    asn1::{ContextSpecific, OctetString, SetOfVec},
};
use pkcs5::pbes2::Salt;
use pkcs12::{PKCS_12_PKCS8_KEY_BAG_OID, pfx::Pfx};
use rand_core::Rng;
use x509_cert::Certificate;

use pkcs12_builder::{
    EncryptionAlgorithm, MacAlgorithm, MacDataBuilder, Pkcs12Builder, add_key_id_attr,
    get_auth_safes, get_cert, get_key, get_key_and_cert, get_safe_bags,
};

#[cfg(test)]
fn check_key_and_cert(
    der_p12: &[u8],
    password: &str,
    key: &[u8],
    cert: &[u8],
    cert_id: &Option<Vec<u8>>,
    key_id: &Option<Vec<u8>>,
) {
    let pfx = Pfx::from_der(der_p12).unwrap();
    let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            // certificate
            let recovered_cert = get_cert(&auth_safe.content, password).unwrap();
            assert_eq!(recovered_cert.cert_der, cert);
            assert_eq!(&recovered_cert.key_id, cert_id);
        } else if ID_DATA == auth_safe.content_type {
            // key
            let recovered_key = get_key(&auth_safe.content, password).unwrap();
            assert_eq!(recovered_key.0, key);
            assert_eq!(&recovered_key.1, key_id);
        }
    }

    let contents = get_key_and_cert(der_p12, password).unwrap();
    assert_eq!(contents.certificate.to_der().unwrap(), cert);
    assert_eq!(contents.key_der, key);
    if key_id.is_some() {
        assert_eq!(&contents.key_id, key_id);
    } else {
        assert_eq!(&contents.key_id, cert_id);
    }

    assert!(get_key_and_cert(der_p12, &format!("{password}X")).is_err());
}
#[cfg(test)]
fn check_algs(
    mac: &MacAlgorithm,
    enc: &EncryptionAlgorithm,
    kdf: &Pbkdf2Prf,
    der_p12: &[u8],
    p12_iterations: u32,
    mac_iterations: u32,
) {
    let pfx = Pfx::from_der(der_p12).unwrap();
    let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();

    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            // certificate
            let enc_data = EncryptedData::from_der(&auth_safe.content.to_der().unwrap()).unwrap();
            assert_eq!(PBES2_OID, enc_data.enc_content_info.content_enc_alg.oid);

            let enc_params = enc_data
                .enc_content_info
                .content_enc_alg
                .parameters
                .as_ref()
                .unwrap()
                .to_der()
                .unwrap();
            let params = pbes2::Parameters::from_der(&enc_params).unwrap();
            assert_eq!(PBKDF2_OID, params.kdf.oid());
            assert_eq!(kdf.oid(), params.kdf.pbkdf2().unwrap().prf.oid());
            assert_eq!(enc.oid(), params.encryption.oid());
            assert_eq!(p12_iterations, params.kdf.pbkdf2().unwrap().iteration_count);
        } else if ID_DATA == auth_safe.content_type {
            // key
            let safe_bags = get_safe_bags(&auth_safe.content).unwrap();
            for safe_bag in safe_bags {
                match safe_bag.bag_id {
                    PKCS_12_PKCS8_KEY_BAG_OID => {
                        let cs: ContextSpecific<EncryptedPrivateKeyInfo<OctetString>> =
                            ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                        assert_eq!(PBES2_OID, cs.value.encryption_algorithm.oid());
                        assert_eq!(
                            p12_iterations,
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .kdf
                                .pbkdf2()
                                .unwrap()
                                .iteration_count
                        );

                        assert_eq!(
                            kdf.oid(),
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .kdf
                                .pbkdf2()
                                .unwrap()
                                .prf
                                .oid()
                        );
                        assert_eq!(
                            enc.oid(),
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .encryption
                                .oid()
                        );
                    }
                    _ => {
                        panic!("Unexpected bag type");
                    }
                }
            }
        } else {
            panic!("Unexpected bag type");
        }
    }

    match pfx.mac_data {
        Some(mac_data) => {
            assert_eq!(mac_iterations as i32, mac_data.iterations);
            assert_eq!(mac.oid(), mac_data.mac.algorithm.oid);
        }
        None => {
            panic!("Missing MAC");
        }
    }
}

#[cfg(test)]
fn check_with_openssl(password: &str, der_p12: &[u8], key: &[u8], cert: &[u8]) {
    use openssl::pkcs12::Pkcs12;
    openssl::init();
    let pkcs12 = Pkcs12::from_der(der_p12).unwrap();
    let p12 = pkcs12.as_ref().parse2(password).unwrap();
    let ossl_cert = p12.cert.unwrap();
    let recovered_cert = ossl_cert.to_der().unwrap();
    let ossl_pkey = p12.pkey.unwrap();
    let recovered_key = ossl_pkey.private_key_to_pkcs8().unwrap();
    assert_eq!(recovered_cert, cert);
    assert_eq!(recovered_key, key);
}

#[allow(clippy::unwrap_used)]
#[test]
fn p12_simple() {
    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    // read this from SubjectAltName
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();
    let der_pfx = Pkcs12Builder::new()
        .iterations(Some(2048))
        .unwrap()
        .key_attributes(Some(key_attrs.clone()))
        .cert_attributes(Some(cert_attrs.clone()))
        .build_with_rng(&cert.clone(), key, "password", &mut rand::rng())
        .unwrap();
    let contents = get_key_and_cert(&der_pfx, "password").unwrap();
    assert_eq!(contents.key_der, key);
    assert_eq!(contents.certificate.to_der().unwrap(), cert_bytes);
    assert_eq!(contents.key_id, Some(key_id.to_vec()));
}

#[test]
fn p12_builder_combinations() {
    let mac_algs = [
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ];
    let enc_algs = [
        EncryptionAlgorithm::Aes128Cbc,
        EncryptionAlgorithm::Aes192Cbc,
        EncryptionAlgorithm::Aes256Cbc,
    ];
    let kdf_algs = [
        Pbkdf2Prf::HmacWithSha256,
        Pbkdf2Prf::HmacWithSha384,
        Pbkdf2Prf::HmacWithSha512,
    ];

    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();
    let password = "password";
    let rng = &mut rand::rng();

    // Spin over various combinations of algorithms...
    for mac in &mac_algs {
        for enc in &enc_algs {
            for kdf in &kdf_algs {
                let mut salt = vec![0_u8; 16];
                rng.fill_bytes(salt.as_mut_slice());

                let mut md = MacDataBuilder::new_with_salt(mac.clone(), salt);
                md.iterations(Some(2048)).unwrap();
                let der_pfx = Pkcs12Builder::new()
                    .iterations(Some(2048))
                    .unwrap()
                    .cert_enc_algorithm(Some(enc.clone()))
                    .key_enc_algorithm(Some(enc.clone()))
                    .cert_kdf_algorithm(Some(*kdf))
                    .key_kdf_algorithm(Some(*kdf))
                    .mac_data_builder(Some(md))
                    .key_attributes(Some(key_attrs.clone()))
                    .cert_attributes(Some(cert_attrs.clone()))
                    .build_with_rng(&cert.clone(), key, password, &mut rand::rng())
                    .unwrap();
                println!("{mac:?}-{enc:?}-{kdf:?}: {}", buffer_to_hex(&der_pfx));

                // Parse with pkcs12 crate and make sure algorithms match expectations
                check_algs(mac, enc, kdf, &der_pfx, 2048, 2048);

                // Make sure openssl can parse the results
                check_with_openssl(password, &der_pfx, key, cert_bytes);

                check_key_and_cert(
                    &der_pfx,
                    password,
                    key,
                    cert_bytes,
                    &Some(key_id.to_vec()),
                    &Some(key_id.to_vec()),
                );
            }
        }
    }
}

#[cfg(test)]
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    std::str::from_utf8(&subtle_encoding::hex::encode_upper(buffer))
        .unwrap_or_default()
        .to_string()
}

#[test]
fn p12_builder_with_defaults_test() {
    let mut p12_builder = Pkcs12Builder::new();
    // This test intentionally uses defaults (600k iterations) to verify default behavior.
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(key_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        600000,
        600000,
    );
}

#[test]
fn p12_builder_test() {
    use hex_literal::hex;

    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    // Cert bag
    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();
    p12_builder.cert_attributes(Some(cert_attrs));

    let cert_kdf_params = Pbkdf2Params {
        salt: Salt::new(hex!("9A A2 77 B5 F0 51 B4 50")).unwrap(),
        iteration_count: 2048,
        key_length: None,
        prf: Pbkdf2Prf::HmacWithSha256,
    };
    let enc_cert_kdf_params = cert_kdf_params.to_der().unwrap();
    let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice()).unwrap();
    let cert_kdf_alg = AlgorithmIdentifierOwned {
        oid: PBKDF2_OID,
        parameters: Some(Any::from(enc_cert_kdf_params_ref)),
    };
    p12_builder.cert_kdf_algorithm_identifier(Some(cert_kdf_alg));

    let cert_iv = OctetString::new(hex!("2E 23 6C 8C 7A 44 0C 3E 0F 4E 0D 32 C9 90 E9 97"))
        .unwrap()
        .to_der()
        .unwrap();
    let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice()).unwrap();
    p12_builder.cert_enc_algorithm_identifier(Some(AlgorithmIdentifier {
        oid: AES_256_CBC_OID,
        parameters: Some(Any::from(cert_iv_ref)),
    }));

    // Key bag
    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();
    p12_builder.key_attributes(Some(key_attrs));

    let key_kdf_params = Pbkdf2Params {
        salt: Salt::new(hex!("10 AF 41 1E 77 84 BA CD")).unwrap(),
        iteration_count: 2048,
        key_length: None,
        prf: Pbkdf2Prf::HmacWithSha256,
    };
    let enc_key_kdf_params = key_kdf_params.to_der().unwrap();
    let enc_key_kdf_params_ref = AnyRef::try_from(enc_key_kdf_params.as_slice()).unwrap();
    let key_kdf_alg = AlgorithmIdentifierOwned {
        oid: PBKDF2_OID,
        parameters: Some(Any::from(enc_key_kdf_params_ref)),
    };
    p12_builder.key_kdf_algorithm_identifier(Some(key_kdf_alg));

    let key_iv = OctetString::new(hex!("46 21 13 61 4C 99 4D 1F DA 70 B4 71 16 5A AE 4A"))
        .unwrap()
        .to_der()
        .unwrap();
    let key_iv_ref = AnyRef::try_from(key_iv.as_slice()).unwrap();
    p12_builder.key_enc_algorithm_identifier(Some(AlgorithmIdentifier {
        oid: AES_256_CBC_OID,
        parameters: Some(Any::from(key_iv_ref)),
    }));

    // Mac
    let mut md_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
    md_builder.iterations(Some(2048)).unwrap();
    md_builder.salt(Some(hex!("FF 08 ED 21 81 C8 A8 E3").to_vec()));
    p12_builder.mac_data_builder(Some(md_builder));

    let orig_p12 = include_bytes!("../tests/examples/example.pfx");
    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder.build(&cert, key, "").unwrap();
    assert_eq!(der_pfx, orig_p12);

    let contents = get_key_and_cert(&der_pfx, "").unwrap();
    assert_eq!(contents.certificate.to_der().unwrap(), cert_bytes);
    assert_eq!(contents.key_der, key);
    assert_eq!(contents.key_id, Some(key_id.to_vec()));
}

#[test]
fn invalid_iterations() {
    let mut p12_builder = Pkcs12Builder::new();
    let oversized: u32 = i32::MAX as u32 + 1;
    assert!(p12_builder.iterations(Some(oversized)).is_err());

    let mut mac_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
    assert!(mac_builder.iterations(Some(oversized)).is_err());
}

#[test]
fn no_mac_data_and_no_key_identifier() {
    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.omit_mac();
    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(&der_pfx, "", key, cert_bytes, &None, &None);
    let pfx = Pfx::from_der(&der_pfx).unwrap();
    assert!(pfx.mac_data.is_none());
}

#[test]
fn p12_builder_iterations_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(key_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2048,
    );
}

#[test]
fn different_iterations_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let rng = &mut rand::rng();
    let mut salt = vec![0_u8; 16];
    rng.fill_bytes(salt.as_mut_slice());

    let mut md = MacDataBuilder::new_with_salt(MacAlgorithm::HmacSha256, salt);
    md.iterations(Some(2049)).unwrap();
    p12_builder.mac_data_builder(Some(md));

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(key_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2049,
    );
}

#[test]
fn different_key_and_cert_ids_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let cert_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &cert_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let rng = &mut rand::rng();
    let mut salt = vec![0_u8; 16];
    rng.fill_bytes(salt.as_mut_slice());

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(key_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2048,
    );
}

#[test]
fn cert_id_only_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let cert_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &cert_id).unwrap();

    let key = include_bytes!("../tests/examples/key.der");
    let cert_bytes = include_bytes!("../tests/examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let rng = &mut rand::rng();
    let mut salt = vec![0_u8; 16];
    rng.fill_bytes(salt.as_mut_slice());

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(cert_id.to_vec()),
        &None,
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2048,
    );
}
