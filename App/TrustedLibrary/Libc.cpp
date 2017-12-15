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
#include "sgx_urts.h"
#include "sgx_capable.h"
#define MAX_MSG_LEN 65536


#define ENCLAVE_PATH L"Enclave.signed.dll"

#pragma comment (lib, "sgx_capable")

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <sgx_urts.h>
#include "Enclave_u.h"
#include "sgx_capable.h"



//void Exit(int code);
/* ecall_libc_functions:
 *   Invokes standard C functions.
 */
//void ecall_libc_functions(void)
//{
//	//sgx_status_t ret = SGX_ERROR_UNEXPECTED;
//
//	//uint32_t bufferlength = (uint32_t)256;
//	////sgx_sha256_hash_t* p_hash = new sgx_sha256_hash_t[bufferlength];
//	//const uint8_t *p_src = (const uint8_t *)"message hash 1";
//	//uint8_t *p_hash = new uint8_t[32];
//	//uint32_t src_len = { 14 };
//	//
//	////printf((char *)p_src);
//
//	//ret = ecall_sgx_sha256_msg(global_eid, p_src, 256);
//	//if (ret != SGX_SUCCESS)
//	//	abort();
//
//
//	//std::string s;
//
//	//s.assign(p_hash, p_hash + sizeof(p_hash));
//	char msg[MAX_MSG_LEN] = { 0 };
//	char out[MAX_MSG_LEN] = { 0 };
//	sgx_launch_token_t token = { 0 };
//	sgx_status_t status;
////	sgx_status_t enclave_error;
//	sgx_enclave_id_t eid = 0;
//	int updated = 0;
//	int rv;
//	int iSGXCapable = 0;
//
//	// = sgx_create_enclavew(ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
//	//if (status != SGX_SUCCESS) { fprintf(stderr, "sgx_create_enclave: 0x%08x\n", status); Exit(1); }
//
//
//
//
//
//	strncpy_s(msg, "password", 80);
//
//	status = store_secret(eid, msg);
//
//	/* Delete the secret from untrusted memory right away */
//	SecureZeroMemory(msg, MAX_MSG_LEN);
//
//	if (status != SGX_SUCCESS) { fprintf(stderr, "ECALL: store_secret: 0x%08x\n", status); Exit(1); }
//
//	//ocall_print_secret(out);
//
//	//status = ecall_print_hash(eid, &rv, &enclave_error);
//
//	get_secret(eid);
//
//	print_hash(eid, &rv);
//
//	if (status != SGX_SUCCESS) { fprintf(stderr, "ECALL: print_hash: 0x%08x\n", status); Exit(1); }
//
//	// Now check the return value of the function executed in the ECALL
//	//if (rv == ERR_HASH) { fprintf(stderr, "Couldn't calculate hash: 0x%08x\n", enclave_error); Exit(1); }
//	//else if (rv == ERR_OCALL) { fprintf(stderr, "OCALL: o_print_hash: 0x%08x\n", enclave_error); Exit(1); }
//
//
//
//
//}

//void Exit(int code)
//{
//	printf("Press ENTER to exit...\n");
//	fflush(stdout);
//	getchar();
//	exit(code);
//}
