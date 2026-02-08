use km_common::algorithms::HpkeAlgorithm;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use lazy_static::lazy_static;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use uuid::Uuid;
use zeroize::Zeroize;

lazy_static! {
    static ref KEY_REGISTRY: KeyRegistry = {
        let registry = KeyRegistry::default();
        registry.start_reaper(Arc::new(AtomicBool::new(false)));
        registry
    };
}

/// Creates a new KEM key record with the specified HPKE algorithm, binding public key, and expiration.
fn create_kem_key(
    algo: HpkeAlgorithm,
    binding_pubkey: &[u8],
    expiry_secs: u64,
) -> Result<KeyRecord, i32> {
    km_common::key_types::create_key_record(algo, expiry_secs, |algo, kem_pub_key| {
        KeySpec::KemWithBindingPub {
            algo,
            kem_public_key: kem_pub_key,
            binding_public_key: binding_pubkey.to_vec(),
        }
    })
}

/// Generates a new KEM keypair associated with a binding public key.
///
/// ## Arguments
/// * `algo` - The HPKE algorithm to use for the keypair.
/// * `binding_pubkey` - A pointer to the binding public key bytes.
/// * `binding_pubkey_len` - The length of the binding public key.
/// * `expiry_secs` - The expiration time of the key in seconds from now.
/// * `out_uuid` - A pointer to a 16-byte buffer where the key UUID will be written.
/// * `out_pubkey` - A pointer to a buffer where the public key will be written.
/// * `out_pubkey_len` - A pointer to a `usize` that contains the size of `out_pubkey` buffer.
///   On success, it will be updated with the actual size of the public key.
///
/// ## Safety
/// This function is unsafe because it dereferences the provided raw pointers.
/// The caller must ensure that:
/// * `binding_pubkey` points to a valid buffer of at least `binding_pubkey_len` bytes.
/// * `out_uuid` is either null or points to a valid 16-byte buffer.
/// * `out_pubkey` is either null or points to a valid buffer of at least `*out_pubkey_len` bytes.
/// * `out_pubkey_len` is either null or points to a valid `usize`.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if an error occurred during key generation or if `binding_pubkey` is null/empty.
/// * `-2` if the `out_pubkey` buffer is too small.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_kem_keypair(
    algo: HpkeAlgorithm,
    binding_pubkey: *const u8,
    binding_pubkey_len: usize,
    expiry_secs: u64,
    out_uuid: *mut u8,
    out_pubkey: *mut u8,
    out_pubkey_len: *mut usize,
) -> i32 {
    if binding_pubkey.is_null() || binding_pubkey_len == 0 {
        return -1;
    }

    let binding_pubkey_slice = unsafe { slice::from_raw_parts(binding_pubkey, binding_pubkey_len) };

    match create_kem_key(algo, binding_pubkey_slice, expiry_secs) {
        Ok(record) => {
            let id = record.meta.id;
            let pubkey = match &record.meta.spec {
                KeySpec::KemWithBindingPub { kem_public_key, .. } => kem_public_key.clone(),
                _ => return -1,
            };
            KEY_REGISTRY.add_key(record);
            unsafe {
                if !out_uuid.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_bytes().as_ptr(), out_uuid, 16);
                }
                if !out_pubkey.is_null() && !out_pubkey_len.is_null() {
                    let buf_len = *out_pubkey_len;
                    if buf_len >= pubkey.len() {
                        std::ptr::copy_nonoverlapping(pubkey.as_ptr(), out_pubkey, pubkey.len());
                        *out_pubkey_len = pubkey.len();
                    } else {
                        return -2; // buffer too small
                    }
                }
            }
            0 // Success
        }
        Err(e) => e,
    }
}

/// Decapsulates a shared secret using a stored KEM key and immediately reseals it using the associated binding public key.
///
/// ## Arguments
/// * `uuid_bytes` - A pointer to the 16-byte UUID of the KEM key.
/// * `encapsulated_key` - A pointer to the encapsulated key bytes (ciphertext from client).
/// * `encapsulated_key_len` - The length of the encapsulated key.
/// * `aad` - A pointer to the Additional Authenticated Data (AAD) for the sealing operation.
/// * `aad_len` - The length of the AAD.
/// * `out_encapsulated_key` - A pointer to a buffer where the new encapsulated key will be written.
/// * `out_encapsulated_key_len` - A pointer to a `usize` containing the size of `out_encapsulated_key`.
///                                On success, updated with the actual size.
/// * `out_ciphertext` - A pointer to a buffer where the sealed ciphertext will be written.
/// * `out_ciphertext_len` - A pointer to a `usize` containing the size of `out_ciphertext`.
///                          On success, updated with the actual size.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if arguments are invalid or key is not found.
/// * `-2` if output buffers are too small.
/// * `-3` if decapsulation fails.
/// * `-4` if sealing (HPKE encryption) fails.
#[unsafe(no_mangle)]
pub extern "C" fn key_manager_decap_and_seal(
    uuid_bytes: *const u8,
    encapsulated_key: *const u8,
    encapsulated_key_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_encapsulated_key: *mut u8,
    out_encapsulated_key_len: *mut usize,
    out_ciphertext: *mut u8,
    out_ciphertext_len: *mut usize,
) -> i32 {
    if uuid_bytes.is_null()
        || encapsulated_key.is_null()
        || encapsulated_key_len == 0
        || out_encapsulated_key.is_null()
        || out_encapsulated_key_len.is_null()
        || out_ciphertext.is_null()
        || out_ciphertext_len.is_null()
    {
        return -1;
    }

    let uuid = unsafe {
        let mut bytes = [0u8; 16];
        std::ptr::copy_nonoverlapping(uuid_bytes, bytes.as_mut_ptr(), 16);
        Uuid::from_bytes(bytes)
    };

    let key_record = match KEY_REGISTRY.get_key(&uuid) {
        Some(record) => record,
        None => return -1,
    };

    let (hpke_algo, binding_public_key) = match &key_record.meta.spec {
        KeySpec::KemWithBindingPub {
            algo,
            binding_public_key,
            ..
        } => (algo, binding_public_key),
        _ => return -1, // Wrong key type
    };

    let kem_algo = match km_common::algorithms::KemAlgorithm::try_from(hpke_algo.kem) {
        Ok(k) => k,
        Err(_) => return -1,
    };

    let enc_key_slice = unsafe { slice::from_raw_parts(encapsulated_key, encapsulated_key_len) };

    // Decapsulate
    let mut shared_secret =
        match km_common::crypto::decaps(key_record.private_key.as_bytes(), enc_key_slice, kem_algo)
        {
            Ok(s) => s,
            Err(_) => return -3,
        };

    let aad_slice = if !aad.is_null() && aad_len > 0 {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    } else {
        &[]
    };

    // Seal
    let (new_enc_key, sealed_ciphertext) = match km_common::crypto::hpke_seal(
        binding_public_key,
        &shared_secret,
        aad_slice,
        hpke_algo,
    ) {
        Ok(res) => res,
        Err(_) => {
            shared_secret.zeroize();
            return -4;
        }
    };
    shared_secret.zeroize();

    // Copy outputs
    unsafe {
        let enc_len_req = new_enc_key.len();
        let ct_len_req = sealed_ciphertext.len();
        let enc_len_avail = *out_encapsulated_key_len;
        let ct_len_avail = *out_ciphertext_len;

        if enc_len_avail < enc_len_req || ct_len_avail < ct_len_req {
            return -2;
        }

        std::ptr::copy_nonoverlapping(new_enc_key.as_ptr(), out_encapsulated_key, enc_len_req);
        *out_encapsulated_key_len = enc_len_req;

        std::ptr::copy_nonoverlapping(sealed_ciphertext.as_ptr(), out_ciphertext, ct_len_req);
        *out_ciphertext_len = ct_len_req;
    }

    0
}

/// Destroys the KEM key associated with the given UUID.
///
/// ## Arguments
/// * `uuid_bytes` - A pointer to a 16-byte buffer containing the key UUID.
///
/// ## Safety
/// This function is unsafe because it dereferences the provided raw pointer.
/// The caller must ensure that `uuid_bytes` points to a valid 16-byte buffer.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if the UUID pointer is null or the key was not found.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_destroy_kem_key(uuid_bytes: *const u8) -> i32 {
    if uuid_bytes.is_null() {
        return -1;
    }
    let uuid = unsafe {
        let mut bytes = [0u8; 16];
        std::ptr::copy_nonoverlapping(uuid_bytes, bytes.as_mut_ptr(), 16);
        Uuid::from_bytes(bytes)
    };

    match KEY_REGISTRY.remove_key(&uuid) {
        Some(_) => 0, // Success
        None => -1,   // Not found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km_common::algorithms::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};

    #[test]
    fn test_create_kem_key_success_and_zeroization() {
        let binding_pubkey = [1u8; 32];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = create_kem_key(algo, &binding_pubkey, 3600);
        assert!(result.is_ok());

        let record = result.unwrap();

        // Verify UUID is present
        assert!(!record.meta.id.is_nil());
    }

    #[test]
    fn test_generate_kem_keypair_ffi_success() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                &mut pubkey_len,
            )
        };

        assert_eq!(result, 0);
        assert_ne!(uuid_bytes, [0u8; 16]);
        assert_eq!(pubkey_len, 32); // X25519 public key is 32 bytes
        assert_ne!(&pubkey_bytes[..32], &[0u8; 32]);
    }

    #[test]
    fn test_generate_kem_keypair_invalid_algo() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: 999, // Invalid KEM
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                &mut pubkey_len,
            )
        };

        assert_eq!(result, -1);
        assert_eq!(uuid_bytes, [0u8; 16]);
    }

    #[test]
    fn test_generate_kem_keypair_null_binding_key() {
        let mut uuid_bytes = [0u8; 16];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                std::ptr::null(), // Null ptr
                32,
                3600,
                uuid_bytes.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        assert_eq!(result, -1);
    }

    #[test]
    fn test_generate_kem_keypair_empty_binding_key_len() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                0, // Empty length
                3600,
                uuid_bytes.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_kem_key_success() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }

        let result = unsafe { key_manager_destroy_kem_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, 0);

        // Second destroy should fail
        let result = unsafe { key_manager_destroy_kem_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_kem_key_not_found() {
        let uuid_bytes = [0u8; 16];
        let result = unsafe { key_manager_destroy_kem_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_kem_key_null_ptr() {
        let result = unsafe { key_manager_destroy_kem_key(std::ptr::null()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_decap_and_seal_success() {
        // 1. Setup binding key (receiver for seal)
        let binding_kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (binding_pk, binding_sk) =
            km_common::crypto::generate_x25519_keypair(binding_kem_algo).unwrap();

        // 2. Generate KEM key in registry
        let mut uuid_bytes = [0u8; 16];
        let mut kem_pubkey_bytes = [0u8; 32];
        let mut kem_pubkey_len = 32;
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        key_manager_generate_kem_keypair(
            algo,
            binding_pk.as_ptr(),
            binding_pk.len(),
            3600,
            uuid_bytes.as_mut_ptr(),
            kem_pubkey_bytes.as_mut_ptr(),
            &mut kem_pubkey_len,
        );

        // 3. Generate a "client" ciphertext/encapsulation targeting KEM key.
        let pt = b"ignored_plaintext";
        let aad = b"test_aad";
        // We use `hpke_seal` to act as the client to generate a valid encapsulation
        let (client_enc, client_ct) =
            km_common::crypto::hpke_seal(&kem_pubkey_bytes, pt, aad, &algo).unwrap();

        // Step 3: Call `decap_and_seal`.
        let mut out_enc_key = [0u8; 32];
        let mut out_enc_key_len = 32;
        let mut out_ct = [0u8; 48]; // 32 bytes secret + 16 tag
        let mut out_ct_len = 48;

        let result = key_manager_decap_and_seal(
            uuid_bytes.as_ptr(),
            client_enc.as_ptr(),
            client_enc.len(),
            aad.as_ptr(),
            aad.len(),
            out_enc_key.as_mut_ptr(),
            &mut out_enc_key_len,
            out_ct.as_mut_ptr(),
            &mut out_ct_len,
        );

        assert_eq!(result, 0);

        // 4. Verify we can decrypt the result using binding_sk
        let recovered_shared_secret =
            km_common::crypto::hpke_open(&binding_sk, &out_enc_key, &out_ct, aad, &algo)
                .expect("Failed to decrypt the resealed secret");

        assert_eq!(recovered_shared_secret.len(), 32);

        // 5. Verify the recovered secret matches what decaps would produce
        let key_record = KEY_REGISTRY.get_key(&Uuid::from_bytes(uuid_bytes)).unwrap();
        let expected_shared_secret = km_common::crypto::decaps(
            key_record.private_key.as_bytes(),
            &client_enc,
            KemAlgorithm::DhkemX25519HkdfSha256,
        )
        .expect("decaps failed");
        assert_eq!(
            recovered_shared_secret, expected_shared_secret,
            "Recovered secret mismatch"
        );

        // 6. Verify that this secret correctly decrypts the original client ciphertext
        // using the shared secret directly instead of the private key.
        let decrypted_pt = km_common::crypto::hpke_open_with_shared_secret(
            &recovered_shared_secret,
            &client_ct,
            aad,
            &algo,
        )
        .expect("Failed to decrypt client message with shared secret");

        assert_eq!(decrypted_pt, pt);
    }

    #[test]
    fn test_decap_and_seal_invalid_uuid() {
        let mut out_enc_key = [0u8; 32];
        let mut out_enc_key_len = 32;
        let mut out_ct = [0u8; 48];
        let mut out_ct_len = 48;

        let result = key_manager_decap_and_seal(
            [0u8; 16].as_ptr(),
            [0u8; 32].as_ptr(),
            32,
            std::ptr::null(),
            0,
            out_enc_key.as_mut_ptr(),
            &mut out_enc_key_len,
            out_ct.as_mut_ptr(),
            &mut out_ct_len,
        );

        assert_eq!(result, -1);
    }

    #[test]
    fn test_decap_and_seal_null_args() {
        let mut out_enc_key = [0u8; 32];
        let mut out_enc_key_len = 32;

        let result = key_manager_decap_and_seal(
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            out_enc_key.as_mut_ptr(),
            &mut out_enc_key_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert_eq!(result, -1);
    }

    #[test]
    fn test_decap_and_seal_decaps_fail() {
        // 1. Setup binding key
        let binding_kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (binding_pk, _) = km_common::crypto::generate_x25519_keypair(binding_kem_algo).unwrap();

        // 2. Generate KEM key
        let mut uuid_bytes = [0u8; 16];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        key_manager_generate_kem_keypair(
            algo,
            binding_pk.as_ptr(),
            binding_pk.len(),
            3600,
            uuid_bytes.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        // 3. Call with invalid encapsulated key (wrong length for X25519)
        let mut out_enc_key = [0u8; 32];
        let mut out_enc_key_len = 32;
        let mut out_ct = [0u8; 48];
        let mut out_ct_len = 48;

        let result = key_manager_decap_and_seal(
            uuid_bytes.as_ptr(),
            [0u8; 31].as_ptr(),
            31,
            std::ptr::null(),
            0,
            out_enc_key.as_mut_ptr(),
            &mut out_enc_key_len,
            out_ct.as_mut_ptr(),
            &mut out_ct_len,
        );

        assert_eq!(result, -3);
    }

    #[test]
    fn test_decap_and_seal_buffer_too_small() {
        // 1. Setup binding key
        let binding_kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (binding_pk, _) = km_common::crypto::generate_x25519_keypair(binding_kem_algo).unwrap();

        // 2. Generate KEM key
        let mut uuid_bytes = [0u8; 16];
        let mut kem_pubkey_bytes = [0u8; 32];
        let mut kem_pubkey_len = 32;
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        key_manager_generate_kem_keypair(
            algo.clone(),
            binding_pk.as_ptr(),
            binding_pk.len(),
            3600,
            uuid_bytes.as_mut_ptr(),
            kem_pubkey_bytes.as_mut_ptr(),
            &mut kem_pubkey_len,
        );

        // 3. Generate valid client encapsulation
        let (client_enc, _) =
            km_common::crypto::hpke_seal(&kem_pubkey_bytes, b"secret", b"", &algo).unwrap();

        // 4. Call with small output buffers
        let mut out_enc_key = [0u8; 31]; // Small
        let mut out_enc_key_len = 31;
        let mut out_ct = [0u8; 47]; // Small
        let mut out_ct_len = 47;

        let result = key_manager_decap_and_seal(
            uuid_bytes.as_ptr(),
            client_enc.as_ptr(),
            client_enc.len(),
            std::ptr::null(),
            0,
            out_enc_key.as_mut_ptr(),
            &mut out_enc_key_len,
            out_ct.as_mut_ptr(),
            &mut out_ct_len,
        );

        assert_eq!(result, -2);
    }
}
