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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "App.h"
#include "Enclave_u.h"

 /* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
	{
		SGX_ERROR_UNEXPECTED,
		"Unexpected error occurred.",
		NULL
	},
	{
		SGX_ERROR_INVALID_PARAMETER,
		"Invalid parameter.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_MEMORY,
		"Out of memory.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_LOST,
		"Power transition occurred.",
		"Please refer to the sample \"PowerTransition\" for details."
	},
	{
		SGX_ERROR_INVALID_ENCLAVE,
		"Invalid enclave image.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ENCLAVE_ID,
		"Invalid enclave identification.",
		NULL
	},
	{
		SGX_ERROR_INVALID_SIGNATURE,
		"Invalid enclave signature.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_EPC,
		"Out of EPC memory.",
		NULL
	},
	{
		SGX_ERROR_NO_DEVICE,
		"Invalid SGX device.",
		"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
	},
	{
		SGX_ERROR_MEMORY_MAP_CONFLICT,
		"Memory map conflicted.",
		NULL
	},
	{
		SGX_ERROR_INVALID_METADATA,
		"Invalid enclave metadata.",
		NULL
	},
	{
		SGX_ERROR_DEVICE_BUSY,
		"SGX device was busy.",
		NULL
	},
	{
		SGX_ERROR_INVALID_VERSION,
		"Enclave version was invalid.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ATTRIBUTE,
		"Enclave was not authorized.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_FILE_ACCESS,
		"Can't open enclave file.",
		NULL
	},
	{
		SGX_ERROR_NDEBUG_ENCLAVE,
		"The enclave is signed as product enclave, and can not be created as debuggable enclave.",
		NULL
	},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
	char token_path[MAX_PATH] = { '\0' };
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: try to retrieve the launch token saved by last transaction
	 *         if there is no token, then create a new one.
	 */
#ifdef _MSC_VER
	 /* try to get the token saved in CSIDL_LOCAL_APPDATA */
	if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
		strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}
	else {
		strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 2);
	}

	/* open the token file */
	HANDLE token_handler = CreateFileA(token_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
	if (token_handler == INVALID_HANDLE_VALUE) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}
	else {
		/* read the token from saved file */
		DWORD read_num = 0;
		ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
#else /* __GNUC__ */
	 /* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;

	if (home_dir != NULL &&
		(strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
	}
	else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
#endif
	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
#ifdef _MSC_VER
		if (token_handler != INVALID_HANDLE_VALUE)
			CloseHandle(token_handler);
#else
		if (fp != NULL) fclose(fp);
#endif
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
	if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (token_handler != INVALID_HANDLE_VALUE)
			CloseHandle(token_handler);
		return 0;
	}

	/* flush the file cache */
	FlushFileBuffers(token_handler);
	/* set access offset to the begin of the file */
	SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

	/* write back the token */
	DWORD write_num = 0;
	WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	CloseHandle(token_handler);
#else /* __GNUC__ */
	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL) fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL) return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
#endif
	return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	printf("%s", str);
}

#if defined(_MSC_VER)
/* query and enable SGX device*/
int query_sgx_status()
{
	sgx_device_status_t sgx_device_status;
	sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
	if (sgx_ret != SGX_SUCCESS) {
		printf("Failed to get SGX device status.\n");
		return -1;
	}
	else {
		switch (sgx_device_status) {
		case SGX_ENABLED:
			return 0;
		case SGX_DISABLED_REBOOT_REQUIRED:
			printf("SGX device has been enabled. Please reboot your machine.\n");
			return -1;
		case SGX_DISABLED_LEGACY_OS:
			printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
			return -1;
		case SGX_DISABLED:
			printf("SGX is not enabled on this platform. More details are unavailable.\n");
			return -1;
		case SGX_DISABLED_SCI_AVAILABLE:
			printf("SGX device can be enabled by a Software Control Interface.\n");
			return -1;
		case SGX_DISABLED_MANUAL_ENABLE:
			printf("SGX device can be enabled manually in the BIOS setup.\n");
			return -1;
		case SGX_DISABLED_HYPERV_ENABLED:
			printf("Detected an unsupported version of Windows* 10 with Hyper-V enabled.\n");
			return -1;
		case SGX_DISABLED_UNSUPPORTED_CPU:
			printf("SGX is not supported by this CPU.\n");
			return -1;
		default:
			printf("Unexpected error.\n");
			return -1;
		}
	}
}
#endif

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <sgx_urts.h>
#include "Enclave_u.h"
#include "sgx_capable.h"

#define ENCLAVE_PATH L"Enclave.signed.dll"
#define MAX_MSG_LEN 65536

#pragma comment (lib, "sgx_capable")

void Exit(int);
void RunSha256();
void RunAesEncryption();

int main()
{
	//RunSha256();
	RunAesEncryption();
}

#define ENCRYPTION_MSG_LEN 65536

void RunAesEncryption() {
	char privateKey[ENCRYPTION_MSG_LEN] = { 0 };
	char unencryptedText[ENCRYPTION_MSG_LEN] = { 0 };
	char incrementCounter[ENCRYPTION_MSG_LEN] = { 0 };
	char out[MAX_MSG_LEN] = { 0 };
	sgx_launch_token_t token = { 0 };
	sgx_status_t status, enclave_error;
	sgx_enclave_id_t eid = 0;
	int updated = 0;
	int rv;
	int iSGXCapable = 0;

	sgx_is_capable(&iSGXCapable);
	//if (iSGXCapable == 0) { MessageBox(0, L"sgx_is_capable == FALSE", L"", 0); Exit(0); }

	status = sgx_create_enclavew(ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if (status != SGX_SUCCESS) { fprintf(stderr, "sgx_create_enclave: 0x%08x\n", status); Exit(1); }

	strncpy_s(privateKey, "572C0706E51A9195", ENCRYPTION_MSG_LEN);
	strncpy_s(unencryptedText, "ante geia", ENCRYPTION_MSG_LEN);
	strncpy_s(incrementCounter, "572C0706E51A9195", ENCRYPTION_MSG_LEN);

	status = store_encryption_data(eid, privateKey, unencryptedText,incrementCounter );

	/* Delete the secret from untrusted memory right away */
	//SecureZeroMemory(msg, MAX_MSG_LEN);

	if (status != SGX_SUCCESS) { fprintf(stderr, "ECALL: store_encryption_data: 0x%08x\n", status); Exit(1); }

	ocall_print_secret(out);

	status = print_encrypted_text(eid, &rv, &enclave_error);
	if (status != SGX_SUCCESS) { fprintf(stderr, "ECALL: print_encrypted_text: 0x%08x\n", status); Exit(1); }

	// Now check the return value of the function executed in the ECALL
	if (rv == -1) { fprintf(stderr, "Couldn't calculate encrypted text: 0x%08x\n", enclave_error); Exit(1); }
	else if (rv == -2) { fprintf(stderr, "OCALL: o_print_text: 0x%08x\n", enclave_error); Exit(1); }


	Exit(0);
}


void RunSha256() {
	char msg[MAX_MSG_LEN] = { 0 };
	char out[MAX_MSG_LEN] = { 0 };
	sgx_launch_token_t token = { 0 };
	sgx_status_t status, enclave_error;
	sgx_enclave_id_t eid = 0;
	int updated = 0;
	int rv;
	int iSGXCapable = 0;

	sgx_is_capable(&iSGXCapable);
	//if (iSGXCapable == 0) { MessageBox(0, L"sgx_is_capable == FALSE", L"", 0); Exit(0); }

	status = sgx_create_enclavew(ENCLAVE_PATH, SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if (status != SGX_SUCCESS) { fprintf(stderr, "sgx_create_enclave: 0x%08x\n", status); Exit(1); }

	strncpy_s(msg, "password", 80);

	status = store_secret(eid, msg);

	/* Delete the secret from untrusted memory right away */
	SecureZeroMemory(msg, MAX_MSG_LEN);

	if (status != SGX_SUCCESS) { fprintf(stderr, "ECALL: store_secret: 0x%08x\n", status); Exit(1); }

	ocall_print_secret(out);

	status = print_hash(eid, &rv, &enclave_error);
	if (status != SGX_SUCCESS) { fprintf(stderr, "ECALL: print_hash: 0x%08x\n", status); Exit(1); }

	// Now check the return value of the function executed in the ECALL
	if (rv == -1) { fprintf(stderr, "Couldn't calculate hash: 0x%08x\n", enclave_error); Exit(1); }
	else if (rv == -2) { fprintf(stderr, "OCALL: o_print_hash: 0x%08x\n", enclave_error); Exit(1); }


	Exit(0);
}

void ocall_print_secret(const char *str)
{
	printf("%s", str);
}

void o_print_hash(unsigned char hash[32])
{
	int i;

	printf("\nSHA-256 hash of your secret (including the newline) is:\n");
	for (i = 0; i < 32; ++i) printf("%02x", hash[i]);
	printf("\n\n");
	puts(
		"Verify this hash by entering your secret in an online SHA256\n"
		"calculator such as:\n\n"
		"  http://passwordsgenerator.net/sha256-hash-generator/\n"
		"  http://www.xorbin.com/tools/sha256-hash-calculator\n"
		"\n(Don't forget to include the trailing newline!)"
	);
}

void o_print_encrypted_text(unsigned char hash[32])
{
	int i;

	printf("\nEncrypted text of the source input (including the newline) is:\n");
	for (i = 0; i < 32; ++i) printf("%02x", hash[i]);
	printf("\n\n");
}

void Exit(int code)
{
	printf("Press ENTER to exit...\n");
	fflush(stdout);
	getchar();
	exit(code);
}


