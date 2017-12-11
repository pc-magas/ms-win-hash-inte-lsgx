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

#include "../App.h"
#include "Enclave_u.h"
#include <sgx_tcrypto.h>
#include <string>

 /* ecall_libc_functions:
  *   Invokes standard C functions.
  */
void ecall_libc_functions(void)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	uint32_t bufferlength = (uint32_t)256;
	//sgx_sha256_hash_t* p_hash = new sgx_sha256_hash_t[bufferlength];
	const uint8_t* p_src = (const uint8_t *)"message hash 1";
	uint8_t *p_hash = new uint8_t[32];
	uint32_t src_len = { 1 };
	ret = ecall_sgx_sha256_msg(global_eid, p_src, 256, p_hash);
	if (ret != SGX_SUCCESS)
		abort();


	std::string s;

	s.assign(p_hash, p_hash + sizeof(p_hash));

	printf("1");
	printf("%s\n", p_hash);
	printf("3");

	/*if ((p_src, src_len, p_hash) > 0) {
		printf("peos ...\n");
		getchar();
		return -1;
	}
	else if (sgx_sha256_msg(p_src, src_len, p_hash) > 0) {

		printf("peos 1...\n");
		getchar();
		return -1;
	}*/
}
