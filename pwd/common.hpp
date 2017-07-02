#pragma once
#include <stdint.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#define MAX_PASSWORD_LENGTH 32

typedef enum
{
	LOG_DEBUG = 0,
	LOG_INFO,
	LOG_ERROR,
	LOG_CRITICAL,
	LOG_INVALID_PRIORITY
} logging_priority_t;

typedef struct {
	uint64_t	id;
	uint8_t		pwd[MAX_PASSWORD_LENGTH];
} user_record_t;

typedef sgx_ec256_dh_shared_t ec256_dh_shared_t;
typedef sgx_cmac_128bit_key_t aes_cmac_128bit_key_t;
typedef sgx_cmac_128bit_tag_t aes_cmac_128bit_tag_t;
typedef sgx_ec256_private_t ec256_private_key_t;
typedef sgx_ec256_public_t ec256_public_key_t;
typedef sgx_aes_ctr_128bit_key_t aes_ctr_128bit_key_t;
typedef sgx_ec256_signature_t ec256_signature_t;
typedef sgx_sha256_hash_t sha256_hash_t;

#define CR_NONCE_SIZE 16
#define SHA256_SIZE (256/8)

#define ECP256_KEY_SIZE 32
#define NISTP_ECP256_KEY_SIZE (ECP256_KEY_SIZE/sizeof(uint32_t))

typedef struct {
	ec256_public_key_t	public_key;
	uint64_t			time;
	// add a signature? seems superfluous
} charesp_client_hello_t;

typedef struct {
	uint8_t				nonce[CR_NONCE_SIZE];
	uint64_t			time;
	ec256_signature_t	signature;
	uint64_t			challenge;
	uint64_t			increment;
} charesp_server_hello_t;

typedef struct {
	uint8_t				nonce[CR_NONCE_SIZE];
	uint64_t			time;
	ec256_signature_t	signature;
	uint64_t			challenge;
	uint64_t			increment;
	sha256_hash_t		hash;
} charesp_client_response_t;

typedef struct {
	uint8_t				nonce[CR_NONCE_SIZE];
	uint64_t			time;
	ec256_signature_t	signature;
	sha256_hash_t		hash;
} charesp_server_response_t;

typedef struct {
	uint8_t				nonce[CR_NONCE_SIZE];
	uint64_t			time;
	ec256_signature_t	signature;
	uint8_t				cipher_text[sizeof(uint64_t) * 2];
} charesp_server_hello_ct_t;

typedef struct {
	uint8_t				nonce[CR_NONCE_SIZE];
	uint64_t			time;
	ec256_signature_t	signature;
	uint8_t				cipher_text[sizeof(sha256_hash_t) + (sizeof(uint64_t) * 2)];
} charesp_client_response_ct_t;

typedef struct
{
	uint8_t				nonce[ CR_NONCE_SIZE ];
	uint64_t			time;
	ec256_signature_t	signature;
	uint8_t				cipher_text[ sizeof(sha256_hash_t) ];
} charesp_server_response_ct_t;

typedef enum {
	CHARESP_STATE_CLIENT_HELLO = 0x00,
	CHARESP_STATE_SERVER_HELLO = 0x01,
	CHARESP_STATE_CLIENT_AUTHENTICATED = 0x02,
	CHARESP_STATE_SERVER_AUTHENTICATED = 0x03,
	CHARESP_STATE_INVALID_VALUE = 0x04
} charesp_state_t;

typedef struct {
	charesp_state_t				state;
	charesp_client_hello_t		client_hello;
	charesp_server_hello_t		server_hello;
	charesp_client_response_t	client_response;
	charesp_server_response_t	server_response;
} charesp_transaction_t;

typedef struct {
	charesp_client_hello_t		client_hello;
	charesp_server_hello_t		server_hello;
	uint64_t					server_challenge;
	uint64_t					client_challenge;
} charesp_hmac_msg_t;
