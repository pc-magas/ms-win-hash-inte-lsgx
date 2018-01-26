/*
 *   Copyright(C) 2011-2017 Intel Corporation All Rights Reserved.
 *
 *   The source code, information  and  material ("Material") contained herein is
 *   owned  by Intel Corporation or its suppliers or licensors, and title to such
 *   Material remains  with Intel Corporation  or its suppliers or licensors. The
 *   Material  contains proprietary information  of  Intel or  its  suppliers and
 *   licensors. The  Material is protected by worldwide copyright laws and treaty
 *   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
 *   modified, published, uploaded, posted, transmitted, distributed or disclosed
 *   in any way  without Intel's  prior  express written  permission. No  license
 *   under  any patent, copyright  or  other intellectual property rights  in the
 *   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
 *   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
 *   intellectual  property  rights must  be express  and  approved  by  Intel in
 *   writing.
 *
 *   *Third Party trademarks are the property of their respective owners.
 *
 *   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
 *   this  notice or  any other notice embedded  in Materials by Intel or Intel's
 *   suppliers or licensors in any way.
 *
 */

#include <string.h>
#include <sgx_cpuid.h>
#include <sgx_tcrypto.h>

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"
#define MAX_MSG_LEN 65536

 /* ecall_malloc_free:
  *   Uses malloc/free to allocate/free trusted memory.
  */
void ecall_malloc_free(void)
{
	void *ptr = malloc(100);
	assert(ptr != NULL);
	memset(ptr, 0x0, 100);
	free(ptr);
}

/* ecall_sgx_cpuid:
 *   Uses sgx_cpuid to get CPU features and types.
 */
void ecall_sgx_cpuid(int cpuinfo[4], int leaf)
{
	sgx_status_t ret = sgx_cpuid(cpuinfo, leaf);
	if (ret != SGX_SUCCESS)
		abort();
}

char secret[MAX_MSG_LEN];
void store_secret(char *s)
{
	strncpy(secret, s, 80);
}
void get_secret()
{
	ocall_print_secret(secret);
}
int print_hash(sgx_status_t *error)
{
	sgx_sha256_hash_t hash;

	*error = sgx_sha256_msg((uint8_t *)secret, (uint32_t)strlen(secret), &hash);
	if (*error != SGX_SUCCESS) return -1;

	*error = o_print_hash((unsigned char *)hash);
	if (*error != SGX_SUCCESS) return -2;

	return 0;
}

#define BIT_SIZE_KEY 128
char encryptionKey[BIT_SIZE_KEY];
char unencryptedText[MAX_MSG_LEN];
char incrementalCounter[BIT_SIZE_KEY];

void store_encryption_data(char *p_key, char *src, char *ctr) {
	strncpy(encryptionKey, p_key, BIT_SIZE_KEY);
	strncpy(unencryptedText, src, MAX_MSG_LEN);
	strncpy(incrementalCounter, ctr, BIT_SIZE_KEY);
}

int print_encrypted_text(sgx_status_t *error) {

	uint8_t result;// = new uint8_t[MAX_MSG_LEN];

	*error = sgx_aes_ctr_encrypt(
		(sgx_aes_ctr_128bit_key_t *)"1",
		(uint8_t *)"1234123412341234",
		16,
		(uint8_t *)"1234123412341234",
		65536,
		&result);
	if (*error != SGX_SUCCESS) return -1;

	o_print_encrypted_text((unsigned char *)result);
	if (*error != SGX_SUCCESS) return -2;

	return 0;
}

void get_encrypted_text() {
	ocall_print_secret(unencryptedText);
}