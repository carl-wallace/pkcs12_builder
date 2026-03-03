//! Utility functions for interacting with ASN.1 structures associated with [PKCS #12 objects](pkcs12::pfx::Pfx)

use log::{error, warn};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

use cms::encrypted_data::EncryptedData;
use const_oid::db::rfc2985::PKCS_9_AT_LOCAL_KEY_ID;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use der::{
    Any, Decode, Encode,
    asn1::{ContextSpecific, OctetString},
};
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs12::{
    AuthenticatedSafe, CertBag, MacData,
    kdf::{Pkcs12KeyType, derive_key_utf8},
    pfx::Pfx,
    safe_bag::SafeContents,
};
use subtle::ConstantTimeEq;
use x509_cert::Certificate;
use x509_cert::attr::Attributes;

use crate::{
    MAX_ITERATION_COUNT,
    error::{Error, Result},
    supported_algs::MacAlgorithm,
};

/// Takes an [Any] that notionally contains an [OctetString] and returns an [AuthenticateSafe](AuthenticatedSafe)
/// object or error.
///
/// The [Any] value is typically the value from the [ContentInfo](cms::content_info::ContentInfo) included in the `auth_safe` field
/// of a [Pfx] object. The resulting [AuthenticatedSafe] contains a vector of
/// [ContentInfo](cms::content_info::ContentInfo) objects
///
/// ```rust,ignore
/// use der::Decode;
/// use pkcs12::pfx::Pfx;
/// use pkcs12_builder::get_auth_safes;
/// // instantiate der_p12
/// let pfx = Pfx::from_der(der_p12).unwrap();
/// let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
/// ```
pub fn get_auth_safes(content: &Any) -> Result<AuthenticatedSafe<'_>> {
    let auth_safes_os = OctetString::from_der(&content.to_der()?)?;
    Ok(AuthenticatedSafe::from_der(auth_safes_os.as_bytes())?)
}

/// Takes an [Any] that notionally contains an [OctetString] and returns a [SafeContents]
/// object or error.
///
/// The [Any] value is typically the value from the [ContentInfo](cms::content_info::ContentInfo) included in an [AuthenticatedSafe]
/// read from the `auth_safe` field of a [Pfx] object. The resulting [SafeContents] contains a vector of
/// [SafeBag](pkcs12::safe_bag::SafeBag) objects
///
/// ```rust,ignore
/// use const_oid::db::rfc5911::ID_DATA;
/// use der::Decode;
/// use pkcs12::pfx::Pfx;
/// use pkcs12_builder::{get_auth_safes, get_safe_bags};
/// // instantiate der_p12
/// let pfx = Pfx::from_der(der_p12).unwrap();
/// let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
/// for auth_safe in &auth_safes {
///     if ID_DATA == auth_safe.content_type {
///         let safe_bags = get_safe_bags(&auth_safe.content).unwrap();
///     }
/// }
/// ```
pub fn get_safe_bags(content: &Any) -> Result<SafeContents> {
    let safe_bags_os = OctetString::from_der(&content.to_der()?)?;
    Ok(SafeContents::from_der(safe_bags_os.as_bytes())?)
}

/// Takes an [Any] that notionally contains an [OctetString] wrapping a [SafeContents] object.
/// Iterates over the [SafeBag](pkcs12::safe_bag::SafeBag) list and decrypts the first bag of type
/// [PKCS_12_PKCS8_KEY_BAG_OID](pkcs12::PKCS_12_PKCS8_KEY_BAG_OID) using the provided password,
/// returning a tuple containing the plaintext key bytes and an optional key identifier. Returns an
/// error if no key bag is found or decryption fails.
pub fn get_key(content: &Any, password: &str) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let safe_bags = get_safe_bags(content)?;
    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID => {
                let key_id = get_key_id(safe_bag.bag_attributes);

                let cs: ContextSpecific<EncryptedPrivateKeyInfo<OctetString>> =
                    ContextSpecific::from_der(&safe_bag.bag_value)?;

                if let Some(pbes2) = cs.value.encryption_algorithm.pbes2() {
                    if let Some(params) = pbes2.kdf.pbkdf2() {
                        if params.iteration_count > MAX_ITERATION_COUNT {
                            return Err(Error::Pkcs12Builder(format!(
                                "The iterations limit exceeded. {} is greater than {}",
                                params.iteration_count, MAX_ITERATION_COUNT
                            )));
                        }
                    }
                }

                let mut ciphertext = cs.value.encrypted_data.as_bytes().to_vec();
                let plaintext = cs
                    .value
                    .encryption_algorithm
                    .decrypt_in_place(password, &mut ciphertext)?;
                return Ok((plaintext.to_vec(), key_id));
            }
            _ => {
                warn!("Unexpected SafeBag type. Ignoring and continuing...");
            }
        };
    }
    Err(Error::Pkcs12Builder(String::from(
        "Failed to find SafeBag containing key",
    )))
}

/// Takes an [Any] that notionally contains an [EncryptedData] whose payload is an encrypted
/// [SafeContents]. Attempts to decrypt the content using the provided password, then extracts and
/// returns a tuple containing the DER-encoded certificate from the first certificate bag found and
/// an optional key identifier.
pub fn get_cert(content: &Any, password: &str) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let enc_data = EncryptedData::from_der(&content.to_der()?)?;

    let enc_params = match enc_data
        .enc_content_info
        .content_enc_alg
        .parameters
        .as_ref()
    {
        Some(r) => r.to_der()?,
        None => {
            return Err(Error::Pkcs12Builder(String::from(
                "Failed to obtain reference to parameters",
            )));
        }
    };

    let params = pkcs5::pbes2::Parameters::from_der(&enc_params)?;
    if let Some(kdf_params) = params.kdf.pbkdf2() {
        if kdf_params.iteration_count > MAX_ITERATION_COUNT {
            return Err(Error::Pkcs12Builder(format!(
                "The iterations limit exceeded. {} is greater than {}",
                kdf_params.iteration_count, MAX_ITERATION_COUNT
            )));
        }
    }

    if let Some(ciphertext_os) = enc_data.enc_content_info.encrypted_content {
        let mut ciphertext = ciphertext_os.as_bytes().to_vec();
        let scheme = pkcs5::EncryptionScheme::from(params.clone());
        let plaintext = scheme.decrypt_in_place(password, &mut ciphertext)?;
        let safe_bags = SafeContents::from_der(plaintext)?;
        for safe_bag in safe_bags {
            match safe_bag.bag_id {
                pkcs12::PKCS_12_CERT_BAG_OID => {
                    let key_id = get_key_id(safe_bag.bag_attributes);

                    let cs: ContextSpecific<CertBag> =
                        ContextSpecific::from_der(&safe_bag.bag_value)?;

                    let cb = cs.value;
                    return Ok((cb.cert_value.as_bytes().to_vec(), key_id));
                }
                _ => {
                    warn!("Unexpected SafeBag type. Ignoring and continuing.");
                }
            };
        }
        error!("Failed to find certificate bag");
        Err(Error::NotFound)
    } else {
        Err(Error::Pkcs12Builder(String::from(
            "Failed to read encrypted content",
        )))
    }
}

/// Takes an optional set of Attributes and returns the first value in the key ID attribute if present.
fn get_key_id(attributes: Option<Attributes>) -> Option<Vec<u8>> {
    if let Some(attributes) = attributes {
        for attribute in attributes.iter() {
            if attribute.oid == PKCS_9_AT_LOCAL_KEY_ID {
                if let Some(value) = attribute.values.iter().next() {
                    return Some(value.value().to_vec());
                }
                warn!("Found a key ID attribute but it had no value. Ignoring and continuing...");
            }
        }
    }
    None
}

/// Takes a DER-encoded [PKCS #12 object](pkcs12::pfx::Pfx) and password, attempts to decrypt it and, if successful, returns
/// a tuple containing a private key, a [Certificate] object, and an optional key identifier.
///
/// This method assumes this basic high-level representation of the structure (though the order of
/// the AuthenticatedSafe elements is unimportant).
///
/// ```text
/// SEQUENCE {          -- PFX
///   SEQUENCE {        -- AuthSafe
///     [0] {
///       SEQUENCE {    -- AuthenticatedSafes
///         SEQUENCE {  -- AuthenticatedSafe
///             contentType: ID_ENCRYPTED_DATA
///             content: SafeContents (including SafeBag of type PKCS_12_CERT_BAG_OID)
///           }
///         SEQUENCE {  -- AuthenticatedSafe
///             contentType: ID_DATA
///             content: SafeContents (including SafeBag of type PKCS_12_PKCS8_KEY_BAG_OID)
///           }
///         }
///       }
///     }
///   SEQUENCE {        -- MacData
///     SEQUENCE {
///       SEQUENCE {
///         }
///       }
///     }
///   }
/// ```
pub fn get_key_and_cert(
    der_p12: &[u8],
    password: &str,
) -> Result<(Vec<u8>, Certificate, Option<Vec<u8>>)> {
    let mut recovered_cert_and_key_id = None;
    let mut recovered_key_and_key_id = None;
    let pfx = Pfx::from_der(der_p12)?;
    let auth_safes_os = OctetString::from_der(&pfx.auth_safe.content.to_der()?)?;
    if let Some(mac_data) = &pfx.mac_data {
        check_mac(password, mac_data, auth_safes_os.as_bytes())?;
    } else {
        warn!(
            "MacData was absent. While this is permitted by the specification, it may indicate a stripping attack."
        );
    }
    let auth_safes = get_auth_safes(&pfx.auth_safe.content)?;
    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            recovered_cert_and_key_id = Some(get_cert(&auth_safe.content, password)?);
        } else if ID_DATA == auth_safe.content_type {
            recovered_key_and_key_id = Some(get_key(&auth_safe.content, password)?);
        }
    }
    if let Some((recovered_cert, cert_id)) = recovered_cert_and_key_id
        && let Some((recovered_key, key_id)) = recovered_key_and_key_id
    {
        let key_id = if key_id.is_some() { key_id } else { cert_id };
        return Ok((
            recovered_key,
            Certificate::from_der(&recovered_cert)?,
            key_id,
        ));
    }
    Err(Error::NotFound)
}

/// Check MAC given a password, an optional MacData and the content to authenticate.
fn check_mac(password: &str, mac_data: &MacData, content: &[u8]) -> Result<()> {
    if mac_data.iterations as u32 > MAX_ITERATION_COUNT {
        return Err(Error::Pkcs12Builder(format!(
            "The iterations limit exceeded. {} is greater than {}",
            mac_data.iterations, MAX_ITERATION_COUNT
        )));
    }

    let md = MacAlgorithm::try_from(mac_data.mac.algorithm.oid)?;

    let mac_key = match md {
        MacAlgorithm::HmacSha256 => derive_key_utf8::<Sha256>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            md.output_size(),
        )?,
        MacAlgorithm::HmacSha384 => derive_key_utf8::<Sha384>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            md.output_size(),
        )?,
        MacAlgorithm::HmacSha512 => derive_key_utf8::<Sha512>(
            password,
            mac_data.mac_salt.as_bytes(),
            Pkcs12KeyType::Mac,
            mac_data.iterations,
            md.output_size(),
        )?,
    };
    let mac = generate_mac(md, &mac_key, content)?;

    match mac.ct_eq(mac_data.mac.digest.as_bytes()).unwrap_u8() {
        1 => Ok(()),
        _ => Err(Error::Pkcs12Builder(String::from(
            "MAC verification failed",
        ))),
    }
}

/// Generate a MAC given a MAC key and content
fn generate_mac(md: MacAlgorithm, mac_key: &[u8], content: &[u8]) -> Result<Vec<u8>> {
    match md {
        MacAlgorithm::HmacSha256 => {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(mac_key)?;
            mac.update(content);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        MacAlgorithm::HmacSha384 => {
            type HmacSha384 = Hmac<Sha384>;
            let mut mac = HmacSha384::new_from_slice(mac_key)?;
            mac.update(content);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        MacAlgorithm::HmacSha512 => {
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(mac_key)?;
            mac.update(content);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}
