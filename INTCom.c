#include "Main.h"
#include "Toolset.h"
#include "BPHide.h"
#include "INTCom.h"
#include "AntiScreenshot.h"

// Global declarations
static void XServiceCall( DWORD dwAuthenticationKey, DWORD dwServiceId, DWORD dwBuffer, DWORD dwBufferSize );
static ULONG *pOrigServiceDescriptorTable = NULL;
static UCHAR *pOrigServiceDescriptorParam = NULL;
static 	ULONG *pNewServiceDescriptorTable = NULL;
static UCHAR *pNewServiceDescriptorParam = NULL;
unsigned int iServiceID = 0; // ID to our service
PServiceDescriptorTableEntry_t KeServiceDescriptorTableShadow = NULL;

#define AUTHKEY 0x56AC149Fl

BOOLEAN AddServiceToTables( VOID )
{
	unsigned int iNewNumberOfServices = 0;
	ULONG uServiceTableBase[] = { (ULONG)XServiceCall };
	UCHAR uParamTableBase[] = { 18 };

	__try
	{
		KdPrint(("Shadow table: 0x%08x Service table: 0x%08x", KeServiceDescriptorTableShadow,
			&KeServiceDescriptorTable));

		// Save orig. system service table and calculate new number of services
		pOrigServiceDescriptorTable = (ULONG*)KeServiceDescriptorTable.ServiceTable;
		pOrigServiceDescriptorParam = KeServiceDescriptorTable.ParamTable;

		iServiceID = KeServiceDescriptorTable.NumberOfServices;
		iNewNumberOfServices = KeServiceDescriptorTable.NumberOfServices+
			(sizeof(uServiceTableBase)/sizeof(uServiceTableBase[0]));
		KdPrint(("Old number of services: %d New: %d", iServiceID, iNewNumberOfServices));

		/* Allocate memory for param table and the system service table */
		pNewServiceDescriptorTable = ExAllocatePoolWithTag( NonPagedPool, iNewNumberOfServices*sizeof(ULONG),
			'SDT1' );
		if( !pNewServiceDescriptorTable )
		{
			KdPrint((""__FUNCTION__": Error on allocating memory"));
			return FALSE;
		}

		pNewServiceDescriptorParam = ExAllocatePoolWithTag( NonPagedPool, iNewNumberOfServices, 'SDT2' );
		if( !pNewServiceDescriptorTable )
		{
			KdPrint((""__FUNCTION__": Error on allocating memory"));
			return FALSE;
		}

		/* Backup existing param table and system service table */
		KdPrint(("Backing up system tables"));
		RtlCopyMemory( pNewServiceDescriptorTable, KeServiceDescriptorTable.ServiceTable,
			KeServiceDescriptorTable.NumberOfServices*sizeof(ULONG) );
		RtlCopyMemory( pNewServiceDescriptorParam, KeServiceDescriptorTable.ParamTable,
			KeServiceDescriptorTable.NumberOfServices );

		/* Append our param table and system service table */
		KdPrint(("Appending our system table"));
		RtlCopyMemory( pNewServiceDescriptorTable+KeServiceDescriptorTable.NumberOfServices,
			uServiceTableBase, sizeof(uServiceTableBase) ); // Servicetable[NumberOfServices] = uServiceTableBase
		RtlCopyMemory( pNewServiceDescriptorParam+KeServiceDescriptorTable.NumberOfServices,
			uParamTableBase, sizeof(uParamTableBase) );

		/* Let the system service table and the param table point to our new ones */
		KdPrint(("Old servicetable: 0x%08x", KeServiceDescriptorTable.ServiceTable));
		KeServiceDescriptorTable.ServiceTable = (PVOID)pNewServiceDescriptorTable;
		KeServiceDescriptorTable.ParamTable = pNewServiceDescriptorParam;
		KeServiceDescriptorTable.NumberOfServices = iNewNumberOfServices;
		KdPrint(("New servicetable: 0x%08x", KeServiceDescriptorTable.ServiceTable));
		/* Also update the first array of the shadow table cause it's the same as
		the system service table */
		KdPrint(("Old shadowtable: 0x%08x", KeServiceDescriptorTableShadow[0].ServiceTable));
		KeServiceDescriptorTableShadow[0].ServiceTable = (PVOID)pNewServiceDescriptorTable;
		KeServiceDescriptorTableShadow[0].ParamTable = pNewServiceDescriptorParam;
		KeServiceDescriptorTableShadow[0].NumberOfServices = iNewNumberOfServices;
		KdPrint(("New shadowtable: 0x%08x", KeServiceDescriptorTableShadow[0].ServiceTable));
		return TRUE;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		KdPrint(("An exception occured while setting new SSDT! Code 0x%08x", GetExceptionCode()));
		return FALSE;
	}
}

BOOLEAN RemoveServiceFromTables( VOID )
{
	/* Just point the shadow and the normal ssdt to original ones */
	KeServiceDescriptorTable.ParamTable = pOrigServiceDescriptorParam;
	KeServiceDescriptorTable.ServiceTable = (PVOID)pOrigServiceDescriptorTable;
	KeServiceDescriptorTable.NumberOfServices = iServiceID;
	KeServiceDescriptorTableShadow[0].ServiceTable = (PVOID)pOrigServiceDescriptorTable;
	KeServiceDescriptorTableShadow[0].ParamTable = pOrigServiceDescriptorParam;
	KeServiceDescriptorTableShadow[0].NumberOfServices = iServiceID;
	/* Free allocated memory */
	ExFreePoolWithTag( pNewServiceDescriptorTable, 'SDT1' );
	ExFreePoolWithTag( pNewServiceDescriptorParam, 'SDT2' );
	return TRUE;
}

void XServiceCall( DWORD dwAuthenticationKey, DWORD dwServiceId, DWORD dwBuffer, DWORD dwBufferSize )
{
	PMDL pMdl = NULL;
	PVOID pSecureAddress = NULL;
	static int iScreenCounter = 0;
	LARGE_INTEGER Sleep;

	if( dwServiceId != X_DRAWING_IS_SAFE )
		KdPrint((""__FUNCTION__"(0x%08x, 0x%08x, 0x%08x, 0x%08x)", dwAuthenticationKey, dwServiceId, dwBuffer, dwBufferSize));

	// Prevent malicious use
	if( dwAuthenticationKey != AUTHKEY )
		return;

    #define GetSecureBuffer(a, s) pMdl = IoAllocateMdl( (PVOID)a, s, FALSE, FALSE, NULL ); \
	MmProbeAndLockPages( pMdl, KernelMode, IoWriteAccess ); \
	pSecureAddress = MmGetSystemAddressForMdlSafe( pMdl, HighPagePriority )
    #define DropBuffer() MmUnlockPages( pMdl ); \
	IoFreeMdl( pMdl )

	// Get a secure buffer
	GetSecureBuffer(dwBuffer, dwBufferSize);
	if( dwServiceId == X_CHECK_PRESENCE )
	{
		//KdPrint((""__FUNCTION__": X_CHECK_PRESENCE"));
		*(unsigned int*)pSecureAddress = TRUE;
	}
	else if( dwServiceId == X_DRAWING_IS_SAFE )
	{
		KeEnterCriticalRegion();
		if( g_bDrawingIsSafe )
		{
			*(unsigned int*)pSecureAddress = TRUE;
			g_bScreenIsSafe = FALSE;
			iScreenCounter = 0;
		}
		else
		{
			*(unsigned int*)pSecureAddress = FALSE;
			iScreenCounter++;
		}

		if( iScreenCounter >= 5 )
		{
			KdPrint(("Screen is safe"));
			g_bScreenIsSafe = TRUE; // Release block so Anti-Cheat can take screenshot, screen is now safe
		}
		KeLeaveCriticalRegion();
	}
	else if( dwServiceId == X_SET_THREAD_CONTEXT )
	{
		((set_thread_context_t*)pSecureAddress)->bSuccess = (UINT)BPInitializeSpoofAndSetContext(
			((set_thread_context_t*)pSecureAddress)->hThread,
			((set_thread_context_t*)pSecureAddress)->pContext,
			(BOOLEAN)((set_thread_context_t*)pSecureAddress)->bSpoofLock);
	}
	else if( dwServiceId == X_SET_DEVICE_HANDLES )
	{
		hDeviceHandle = ((device_handles_t*)pSecureAddress)->hClientAreaDC;
		hClientArea = ((device_handles_t*)pSecureAddress)->hWindowDC;
	}

	DropBuffer( );
}
