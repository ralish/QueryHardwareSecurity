#include "pch.h"

__declspec(dllexport)
void* __RPC_USER MIDL_user_allocate(const size_t cBytes) {
    return malloc(cBytes);
}

__declspec(dllexport)
void __RPC_USER MIDL_user_free(void* pBuffer) {
    free(pBuffer);
}
