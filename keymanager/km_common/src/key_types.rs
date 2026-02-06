use crate::algorithms::{HpkeAlgorithm, KemAlgorithm};
use crate::crypto;
use crate::protected_mem::Vault;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroize;

#[cfg(not(test))]
const REAPER_INTERVAL_SECS: u64 = 60;
#[cfg(test)]
const REAPER_INTERVAL_SECS: u64 = 1;

/// Represents the purpose of the Key and its associated algorithms.
#[derive(Clone)]
pub enum KeySpec {
    // Represents the composite key used by the Key Protection Service for the decaps-and-encrypt flow.
    KemWithBindingPub {
        // The KEM and binding public keys share the same algorithm suite.
        algo: HpkeAlgorithm,
        kem_public_key: Vec<u8>,     // The KEM public key
        binding_public_key: Vec<u8>, // Binding public key for HPKE encrypt after decaps
    },
    Binding {
        algo: HpkeAlgorithm,
        binding_public_key: Vec<u8>, // The Binding key-pair
    },
}

// Internal Rust struct to hold the Key Metadata
#[derive(Clone)]
pub struct KeyMetadata {
    pub id: Uuid,              // UUID key handle for internal tracking
    pub created_at: Instant,
    pub delete_after: Instant, // TTL-bound deletion time
    pub spec: KeySpec,         // (non-secret) Cryptographic material
}

pub struct KeyRecord {
    pub meta: KeyMetadata,
    pub private_key: Vault, // memfd_secrets backed secret key-material
}

pub type KeyHandle = Uuid;

#[derive(Default, Clone)]
pub struct KeyRegistry {
    keys: Arc<RwLock<HashMap<KeyHandle, Arc<KeyRecord>>>>,
}

impl KeyRegistry {
    pub fn add_key(&self, record: KeyRecord) {
        let mut keys = self.keys.write().unwrap();
        keys.insert(record.meta.id, Arc::new(record));
    }

    pub fn remove_key(&self, id: &KeyHandle) -> Option<Arc<KeyRecord>> {
        let mut keys = self.keys.write().unwrap();
        keys.remove(id)
    }

    pub fn get_key(&self, id: &KeyHandle) -> Option<Arc<KeyRecord>> {
        let keys = self.keys.read().unwrap();
        keys.get(id).and_then(|record| {
            if record.meta.delete_after > Instant::now() {
                Some(Arc::clone(record))
            } else {
                None
            }
        })
    }

    /// Spawns a background reaper thread to walk through the KeyRegistry every 60s and sanitize expired keys.
    pub fn start_reaper(&self, stop_signal: Arc<std::sync::atomic::AtomicBool>) -> std::thread::JoinHandle<()> {
        let keys_clone = Arc::clone(&self.keys);
        std::thread::spawn(move || {
            while !stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(REAPER_INTERVAL_SECS));
                if stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let now = Instant::now();
                // We only expire KemWithBindingPub keys as per requirements.
                keys_clone.write().unwrap().retain(|_, key| {
                    match key.meta.spec {
                        KeySpec::KemWithBindingPub { .. } => key.meta.delete_after > now,
                        _ => true,
                    }
                });
            }
        })
    }
}

/// Helper function to create a KeyRecord and generate the underlying keypair.
pub fn create_key_record<F>(
    algo: HpkeAlgorithm,
    expiry_secs: u64,
    spec_builder: F,
) -> Result<KeyRecord, i32>
where
    F: FnOnce(HpkeAlgorithm, Vec<u8>) -> KeySpec,
{
    let (pub_key, mut priv_key) = match KemAlgorithm::try_from(algo.kem)
        .ok()
        .and_then(|k| crypto::generate_x25519_keypair(k).ok())
    {
        Some(pair) => pair,
        None => return Err(-1),
    };

    let id = Uuid::new_v4();
    let vault = Vault::new(&priv_key);
    priv_key.zeroize();
    let vault = vault.map_err(|_| -1)?;

    let record = KeyRecord {
        meta: KeyMetadata {
            id,
            created_at: Instant::now(),
            delete_after: Instant::now() + Duration::from_secs(expiry_secs),
            spec: spec_builder(algo, pub_key),
        },
        private_key: vault,
    };

    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};

    #[test]
    fn test_create_key_record_success() {
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let expiry = 3600;

        let result = create_key_record(algo, expiry, |a, pk| KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        });

        assert!(result.is_ok());
        let record = result.unwrap();

        // Check metadata
        assert!(!record.meta.id.is_nil());
        assert!(record.meta.delete_after > record.meta.created_at);
        
        // Check spec
        if let KeySpec::Binding { algo: ref a, binding_public_key: ref pk } = record.meta.spec {
            assert_eq!(a.kem, algo.kem);
            assert_eq!(pk.len(), 32);
        } else {
            panic!("Unexpected KeySpec variant");
        }
    }

    #[test]
    fn test_create_key_record_kem_with_binding_pub_success() {
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let binding_pubkey = [42u8; 32];
        let expiry = 3600;

        let result = create_key_record(algo, expiry, |a, pk| KeySpec::KemWithBindingPub {
            algo: a,
            kem_public_key: pk,
            binding_public_key: binding_pubkey.to_vec(),
        });

        assert!(result.is_ok());
        let record = result.unwrap();

        if let KeySpec::KemWithBindingPub { algo: ref a, kem_public_key: ref kpk, binding_public_key: ref bpk } = record.meta.spec {
            assert_eq!(a.kem, algo.kem);
            assert_eq!(kpk.len(), 32);
            assert_eq!(bpk, &binding_pubkey.to_vec());
        } else {
            panic!("Unexpected KeySpec variant");
        }
    }

    #[test]
    fn test_add_key() {
        let registry = KeyRegistry::default();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        
        let record = create_key_record(algo, 3600, |a, pk| KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        }).expect("failed to create key");

        let id = record.meta.id;
        registry.add_key(record);

        // Access private field for testing
        let keys = registry.keys.read().unwrap();
        assert!(keys.contains_key(&id));
        assert_eq!(keys.get(&id).unwrap().meta.id, id);
    }

    #[test]
    fn test_remove_key() {
        let registry = KeyRegistry::default();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        
        let record = create_key_record(algo, 3600, |a, pk| KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        }).expect("failed to create key");

        let id = record.meta.id;
        registry.add_key(record);
        assert!(registry.remove_key(&id).is_some());
        assert!(registry.remove_key(&id).is_none());
    }

    #[test]
    fn test_get_key_liveness() {
        let registry = KeyRegistry::default();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        
        // Key that expires in 0 seconds (already expired)
        let record = create_key_record(algo, 0, |a, pk| KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        }).expect("failed to create key");

        let id = record.meta.id;
        registry.add_key(record);

        // Should be None because it's expired
        assert!(registry.get_key(&id).is_none());

        // Key that is still alive
        let record2 = create_key_record(algo, 3600, |a, pk| KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        }).expect("failed to create key");

        let id2 = record2.meta.id;
        registry.add_key(record2);
        assert!(registry.get_key(&id2).is_some());
    }

    #[test]
    fn test_reaper_functionality() {
        let registry = KeyRegistry::default();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        // Create a key that expires in 2 seconds (reaper interval is 1s in test)
        // We use KemWithBindingPub because the reaper logic specifically targets this type.
        let binding_pubkey = [42u8; 32];
        let expiry = 2;
        let record = create_key_record(algo, expiry, |a, pk| KeySpec::KemWithBindingPub {
            algo: a,
            kem_public_key: pk,
            binding_public_key: binding_pubkey.to_vec(),
        }).expect("failed to create key");
        
        let id = record.meta.id;
        registry.add_key(record);

        // Start reaper
        let stop_signal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = registry.start_reaper(stop_signal.clone());

        // Wait for < expiry (1s) - key should still be there
        std::thread::sleep(Duration::from_secs(1));
        assert!(registry.get_key(&id).is_some());

        // Wait for > expiry (2s total) - key should be gone (reaper runs every 1s)
        std::thread::sleep(Duration::from_secs(2));
        
        // Check raw storage directly to verify reaper removed it, 
        // as get_key() also filters by expiry.
        {
            let keys = registry.keys.read().unwrap();
            assert!(!keys.contains_key(&id), "Key should have been removed by reaper");
        }

        // Clean up
        stop_signal.store(true, std::sync::atomic::Ordering::Relaxed);
        handle.join().unwrap();
    }
}
