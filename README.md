# pkcs12_builder

Standalone library crate for building and parsing PKCS #12 objects.

[PKCS #12](https://datatracker.ietf.org/doc/html/rfc7292) defines a portable format for storing and transporting a user's private keys and certificates. 
This crate provides [Pkcs12Builder] for creating a `Pfx` containing one certificate and one private key, both protected with password-based encryption (PBES2 / PBKDF2 by default) and a password-based MAC
and [MacDataBuilder] for creating the `MacData` structure included in a `Pfx`.

## Quick start

```rust,ignore
// instantiate key and cert variables
let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

let mut cert_attrs = SetOfVec::new();
add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

let mut key_attrs = SetOfVec::new();
add_key_id_attr(&mut key_attrs, &key_id).unwrap();
let der_pfx = Pkcs12Builder::new()
.key_attributes(Some(key_attrs.clone()))
.cert_attributes(Some(cert_attrs.clone()))
.build_with_rng(&cert.clone(), key, "password", &mut OsRng).unwrap();
let (recovered_key, recovered_cert, recovered_key_id) = get_key_and_cert(&der_pfx, "password").unwrap();
assert_eq!(recovered_key, key);
assert_eq!(recovered_cert.to_der().unwrap(), cert_bytes);
```
