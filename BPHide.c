#include "Main.h"
#include "Toolset.h"
#include "Detour.h"
#include "BPHide.h"

// Global declarations
BOOLEAN m_bSpoofLock = FALSE;
PETHREAD m_hSpoofThread = NULL;
CONTEXT m_cSpoofContext = { 0 };

PsSetContextThread_t PsSetContextThread = NULL;
PsGetContextThread_t PsGetContextThread = NULL;

PsSetContextThread_t ogPsSetContextThread = NULL;
PsGetContextThread_t ogPsGetContextThread = NULL;

DetourObject_t* dtPsSetContextThread = NULL;
DetourObject_t* dtPsGetContextThread = NULL;

NTSTATUS NTAPI hkPsGetContextThread( PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode );
NTSTATUS NTAPI hkPsSetContextThread( PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode );

BOOLEAN BPInitializeHooks( void )
{
	DWORD dwPsGetContextThread = 0;
	DWORD dwPsSetContextThread = 0;

	ReadEAT( g_pKrnlBase, "PsGetContextThread", &dwPsGetContextThread );
	ReadEAT( g_pKrnlBase, "PsSetContextThread", &dwPsSetContextThread );
	if( !dwPsSetContextThread || !dwPsGetContextThread )
		return FALSE;

	KdPrint((""__FUNCTION__": Setting detours to PsGetContextThread and PsGetContextThread"));

	PsSetContextThread = (PsSetContextThread_t)dwPsSetContextThread;
	PsGetContextThread = (PsGetContextThread_t)dwPsGetContextThread;

	dtPsSetContextThread = DtCreateDetour( dwPsSetContextThread, (ULONG)&hkPsSetContextThread );
	dtPsGetContextThread = DtCreateDetour( dwPsGetContextThread, (ULONG)&hkPsGetContextThread );
	if( !dtPsSetContextThread || !dtPsGetContextThread )
		return FALSE;

	ogPsSetContextThread = (PsSetContextThread_t)dtPsSetContextThread->Trampoline;
	ogPsGetContextThread = (PsGetContextThread_t)dtPsGetContextThread->Trampoline;

	return TRUE;
}

VOID BPDestroyHooks( void )
{
	DtKillDetour(dtPsGetContextThread);
	DtKillDetour(dtPsSetContextThread);
}

BOOLEAN BPInitializeSpoofAndSetContext( HANDLE hThread, CONTEXT *pContext, BOOLEAN bSpoofLock )
{
	NTSTATUS ntStatus = FALSE;
	PETHREAD Thread;

	KdPrint((""__FUNCTION__": SpoofLock %d hThread: 0x%08x pContext: 0x%08x", bSpoofLock, hThread, pContext));

	// Reset current thread and spooflock
	m_bSpoofLock = FALSE;
	m_hSpoofThread = NULL;

	ntStatus = ObReferenceObjectByHandle( hThread, THREAD_SET_CONTEXT|THREAD_GET_CONTEXT, *PsThreadType,
		KernelMode, (PVOID*)&Thread, NULL );
	if( !NT_SUCCESS(ntStatus) )
		return FALSE;

	PsGetContextThread( Thread, &m_cSpoofContext, KernelMode );
	ntStatus = PsSetContextThread( Thread, pContext, UserMode );
	if( !NT_SUCCESS(ntStatus) )
	{
		ObDereferenceObject( Thread );
		return FALSE;
	}

	m_hSpoofThread = Thread;
	m_bSpoofLock = bSpoofLock;
	return TRUE;
}

NTSTATUS NTAPI hkPsSetContextThread( PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	KdPrint(("hkPsSetContextThread called"));

	if( m_bSpoofLock && m_hSpoofThread )
	{
		if( m_hSpoofThread == Thread )
		{
			KdPrint(("hkPsSetThreadContext on spoofed thread. Storing context and returning success"));
			memcpy(&m_cSpoofContext, ThreadContext, sizeof(CONTEXT));
			return ntStatus;
		}
	}

	return ogPsSetContextThread(Thread, ThreadContext, PreviousMode);
}

NTSTATUS NTAPI hkPsGetContextThread( PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE PreviousMode )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PMDL pMdl = NULL;
	PVOID pSecureAddress = NULL;

	KdPrint(("hkPsGetContextThread called"));

   #define GetSecureBuffer(a, s) pMdl = IoAllocateMdl( (PVOID)a, s, FALSE, FALSE, NULL ); \
	MmProbeAndLockPages( pMdl, KernelMode, IoWriteAccess ); \
	pSecureAddress = MmGetSystemAddressForMdlSafe( pMdl, HighPagePriority )
   #define DropBuffer() MmUnlockPages( pMdl ); \
	IoFreeMdl( pMdl )

	if( m_bSpoofLock && m_hSpoofThread )
	{
		if( m_hSpoofThread == Thread )
		{
			KdPrint(("hkPsGetThreadContext on spoofed thread. Returning fake context."));
			ntStatus = ogPsGetContextThread(Thread, ThreadContext, PreviousMode);
			GetSecureBuffer(ThreadContext, sizeof(CONTEXT));
			memcpy(pSecureAddress, &m_cSpoofContext, sizeof(CONTEXT));
			DropBuffer();
			return ntStatus;
		}
	}
	return ogPsGetContextThread(Thread, ThreadContext, PreviousMode);
}
