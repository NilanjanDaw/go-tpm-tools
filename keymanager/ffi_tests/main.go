package main

/*
#cgo LDFLAGS: -L../target/debug -lkps_key_custody_core -lstdc++ -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    int32_t kem;
    int32_t kdf;
    int32_t aead;
} HpkeAlgorithm;

int32_t key_manager_generate_kem_keypair(
    HpkeAlgorithm algo,
    const uint8_t *binding_pubkey,
    size_t binding_pubkey_len,
    uint64_t expiry_secs,
    uint8_t *out_uuid,
    uint8_t *out_pubkey,
    size_t *out_pubkey_len
);
*/
import "C"
import (
	"ffi_tests/algorithms"
	"fmt"
	"unsafe"
)

func main() {
	algo := C.HpkeAlgorithm{
		kem:  C.int32_t(algorithms.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256),
		kdf:  C.int32_t(algorithms.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256),
		aead: C.int32_t(algorithms.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM),
	}

	bindingPubKey := make([]byte, 32)
	for i := range bindingPubKey {
		bindingPubKey[i] = byte(i)
	}

	outUUID := make([]byte, 16)
	outPubKey := make([]byte, 64)
	outPubKeyLen := C.size_t(len(outPubKey))

	res := C.key_manager_generate_kem_keypair(
		algo,
		(*C.uint8_t)(unsafe.Pointer(&bindingPubKey[0])),
		C.size_t(len(bindingPubKey)),
		3600,
		(*C.uint8_t)(unsafe.Pointer(&outUUID[0])),
		(*C.uint8_t)(unsafe.Pointer(&outPubKey[0])),
		&outPubKeyLen,
	)

	if res != 0 {
		fmt.Printf("Error generating KEM keypair: %d\n", res)
		return
	}

	fmt.Printf("Successfully generated KEM keypair!\n")
	fmt.Printf("UUID: %x\n", outUUID)
	fmt.Printf("PubKey: %x\n", outPubKey[:outPubKeyLen])
}
