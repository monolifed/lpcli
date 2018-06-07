#ifndef __PBKDF2_HMAC_SHA256_H__
#define __PBKDF2_HMAC_SHA256_H__

#include <stdint.h>
void pbkdf2_sha256(const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen,
	uint32_t rounds, uint8_t *dk, uint32_t dklen);

#endif // __PBKDF2_HMAC_SHA256_H__
