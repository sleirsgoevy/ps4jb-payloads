#pragma once
#include <stdint.h>

int pfs_derive_fake_keys(const uint8_t* p_eekpfs, const uint8_t* crypt_seed, uint8_t* ek, uint8_t* sk);
int pfs_hmac_virtual(uint8_t* out, const uint8_t* key, uint64_t data, size_t data_size);
int pfs_xts_virtual(uint64_t dst, uint64_t src, const uint8_t* key, uint64_t start, uint32_t count, int is_encrypt);
