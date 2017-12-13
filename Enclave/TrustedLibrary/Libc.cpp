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

void ecall_sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len)
{

	printf("AAAAAAAAAAAAAAAAA\n");
	sgx_sha256_hash_t *result = new sgx_sha256_hash_t[32];

	sgx_status_t ret = sgx_sha256_msg(p_src, src_len, result);
	if (ret != SGX_SUCCESS)
		abort();


	printf("----------------------------Hash Result as %s: ----------------------------\n");
	printf((char *)result[0]);
	printf("\n");
	printf("----------------------------End of Result as %s: ----------------------------\n");



	printf("----------------------------Hash Result as char array: ----------------------------\n");
	printf((char *)result);
	printf("\n");
	printf("----------------------------End of Hash Result as char array: ----------------------------\n");
	printf("BBBBBBBBBBBBBBBBB\n");



	printf("----------------------------Hash Result as hex array: ----------------------------\n");
	for (int i = 0; i < 32; i++) {
		printf("%#x, ", (int)&result[i]);
	}
	printf("\n");
	printf("----------------------------End of Hash Result as hex array: ----------------------------\n");

}


