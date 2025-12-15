#include "pch.h"

#if defined(_M_ARM64)
#include "RpcLsaIsoStatus-ARM64.c"  // NOLINT(bugprone-suspicious-include)
#elif defined(_M_X64) || defined(_M_IX86)
#include "RpcLsaIsoStatus-x64.c"  // NOLINT(bugprone-suspicious-include)
#endif

__declspec(dllexport)
_Success_(return == RPC_S_OK)
LONG LsaIsoStatus_GetRunningServices(const _Out_ PLONG Result) {
    *Result = 0;

    RPC_STATUS status;
    RPC_WSTR wszBinding = NULL;
    RPC_BINDING_HANDLE hBinding = NULL;
    LONG lsaIsoRunningServices = 0;

    status = RpcStringBindingComposeW(NULL, L"ncalrpc", NULL, L"LSA_ISO_RPC_SERVER", NULL, &wszBinding);
    if (status != RPC_S_OK) { goto Return; }

    status = RpcBindingFromStringBindingW(wszBinding, &hBinding);
    if (status != RPC_S_OK) { goto Return; }

    lsaIsoRunningServices = GetRunningServices(hBinding);
    *Result = lsaIsoRunningServices;

Return:
    if (hBinding != NULL) { RpcBindingFree(&hBinding); }
    if (wszBinding != NULL) { RpcStringFreeW(&wszBinding); }
    return status;
}
