#ifndef __BPHIDE__H
#define __BPHIDE__H

typedef NTSTATUS(NTAPI *PsSetContextThread_t)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode);
typedef NTSTATUS(NTAPI *PsGetContextThread_t)(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode);

BOOLEAN BPInitializeHooks( void );
VOID BPDestroyHooks( void );
BOOLEAN BPInitializeSpoofAndSetContext( HANDLE hThread, CONTEXT *pContext, BOOLEAN bSpoofLock );

#endif
