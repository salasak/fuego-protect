// Note: Read device name from registry
#include "Main.h"
#include "Toolset.h"
#include "BPHide.h"
#include "AntiScreenshot.h"
#include "ModuleHide.h"

/* Fuego Protect is an universal device driver for Vista and XP 32Bit
   which is designed to cloak a modules memory and setten hardware
   breakpoints aswell catch all screenshot calls made by an Anti-Cheat
*/

// Global declarations
wchar_t DeviceName[128];
wchar_t DosDeviceName[128];
static PDEVICE_OBJECT g_Device = NULL;
static ULONG g_uProcessNameOffset = 0;
static PMODULE_ENTRY g_psLoadedModuleList = NULL;
PVOID g_pKrnlBase = NULL;
char szKernelName[256] = { 0 };

PServiceDescriptorTableEntry_t KeServiceDescriptorTableShadow = NULL;


VOID DriverUnload( IN PDRIVER_OBJECT pDriverObject );
NTSTATUS OnDispatch( IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp );

ULONG FindPsLoadedModuleList( PDRIVER_OBJECT DriverObject )
{
	PMODULE_ENTRY psReturnEntry = NULL;

	if( !DriverObject )
		return 0;

	psReturnEntry = *((PMODULE_ENTRY*)((ULONG)DriverObject + 0x14));

	return (ULONG)psReturnEntry;
}

ULONG UnlinkDriverEntry( PDRIVER_OBJECT DriverObject )
{
	if( g_psLoadedModuleList && DriverObject->DriverStart )
	{
		PMODULE_ENTRY pm_current = g_psLoadedModuleList;

		while((PMODULE_ENTRY)pm_current->le_mod.Flink != g_psLoadedModuleList)
		{
			if ((pm_current->unk1 != 0x00000000) && (pm_current->driver_Path.Length != 0))
			{
				if((ULONG)DriverObject->DriverStart == pm_current->base)
				{
					*((PULONG)pm_current->le_mod.Blink) = (ULONG)pm_current->le_mod.Flink;
					pm_current->le_mod.Flink->Blink = pm_current->le_mod.Blink;
					return 1;
				}
			}

			pm_current = (MODULE_ENTRY*)pm_current->le_mod.Flink;
		}
	}

	return 0;
}

BOOLEAN GetProcessNameOffset( void )
{
	ULONG uCount = 0;
	ULONG uCurrentProc = (ULONG)PsGetCurrentProcess( );
	for( ; uCount < PAGE_SIZE*3; uCount++ )
	{
		if( !strncmp("System", (PCCHAR)uCurrentProc+uCount, strlen("System")) )
		{
			// We found the offset
			g_uProcessNameOffset = uCount;
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN GetProcessName( OUT PCHAR pszName, IN PEPROCESS peProcess )
{
	if( g_uProcessNameOffset != 0 && pszName && peProcess )
	{
		PCHAR pszProcessName = (PCHAR)peProcess+g_uProcessNameOffset;
		strncpy( pszName, pszProcessName, 16 );
		pszName[16] = '\0';
		return TRUE;
	}
	return FALSE;
}

NTSTATUS DriverEntry( IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryString )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING uDeviceName, uDosDeviceName;
	UNICODE_STRING uKeyName;
	unsigned int iCount = 0;
	PVOID pStackAttach = NULL;

	OBJECT_ATTRIBUTES KeyAttributes;
	HANDLE KeyHandle;
	ULONG uLength = 0;
	KEY_VALUE_BASIC_INFORMATION* KeyValueInformation = NULL;
	WCHAR *NamePtr = NULL;
	ULONG NameOffset;

	RtlInitUnicodeString( &uKeyName, L"DisplayName" );
	InitializeObjectAttributes( &KeyAttributes, pRegistryString, OBJ_KERNEL_HANDLE, NULL, NULL );
	ntStatus = ZwOpenKey( &KeyHandle, KEY_QUERY_VALUE, &KeyAttributes );
	if( !NT_SUCCESS(ntStatus) )
	{
		KdPrint(("Error opening Key %wZ", pRegistryString));
		return ntStatus;
	}
	ntStatus = ZwQueryValueKey( KeyHandle, &uKeyName, KeyValueBasicInformation, &KeyValueInformation, 0, &uLength );
	if( !NT_SUCCESS(ntStatus) )
	{
		KdPrint(("Error determining return length for ZwQueryValueKey"));
		return ntStatus;
	}
	KeyValueInformation = (KEY_VALUE_BASIC_INFORMATION*)ExAllocatePool( NonPagedPool, uLength );
	ntStatus = ZwQueryValueKey( KeyHandle, &uKeyName, KeyValueBasicInformation, KeyValueInformation, uLength, &uLength );
	if( !NT_SUCCESS(ntStatus) )
	{
		KdPrint(("Error getting value of the key"));
		return ntStatus;
	}

	NameOffset = ((ULONG)&(((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Name)) - ((ULONG)KeyValueInformation);
	NamePtr = (WCHAR*)((PBYTE)KeyValueInformation + NameOffset);

	if( !NameOffset || !NamePtr )
	{
		KdPrint(("Error: NameOffset or NamePtr invalid"));
		return STATUS_UNSUCCESSFUL;
	}

	wcscpy(DeviceName, L"\\Device\\");
	wcscat(DeviceName, NamePtr);

	wcscpy(DosDeviceName, L"\\DosDevices\\");
	wcscat(DosDeviceName, NamePtr);

	RtlInitUnicodeString( &uDeviceName, DeviceName );
	RtlInitUnicodeString( &uDosDeviceName, DosDeviceName );

	KdPrint(("Name: %Wz %wZ\n",&uDeviceName, &uDosDeviceName));
	ExFreePool(KeyValueInformation);

	ntStatus = IoCreateDevice( pDriverObject, 0, &uDeviceName,
		FILE_DEVICE_UNKNOWN, 0, TRUE, &g_Device );
	if( !NT_SUCCESS(ntStatus) )
	{
		KdPrint(("Fail on IoCreateDevice. ntStatus: 0x%08x", ntStatus));
		return ntStatus;
	}

	ntStatus = IoCreateSymbolicLink( &uDosDeviceName, &uDeviceName );
	if( !NT_SUCCESS(ntStatus) )
	{
		KdPrint(("Fail on IoCreateSymbolicLink. ntStatus: 0x%08x", ntStatus));
		IoDeleteDevice( pDriverObject->DeviceObject );
		return ntStatus;
	}

	KdPrint(("Loading driver. pDriverObject 0x%08x pRegistryString 0x%08x Build at "__TIME__" "__DATE__"",
		pDriverObject, pRegistryString));
	pDriverObject->DriverUnload = DriverUnload;
	for( iCount = 0; iCount < IRP_MJ_MAXIMUM_FUNCTION; iCount++ )
		pDriverObject->MajorFunction[iCount] = OnDispatch;

	// Retrieve module list and unlink driver
	g_psLoadedModuleList = (PMODULE_ENTRY)FindPsLoadedModuleList( pDriverObject );
	if( !g_psLoadedModuleList )
	{
		KdPrint(("Error retrieving module list!"));
		ntStatus = STATUS_UNSUCCESSFUL;
		IoDeleteSymbolicLink( &uDosDeviceName );
		IoDeleteDevice( pDriverObject->DeviceObject );
		return ntStatus;
	}
	UnlinkDriverEntry( pDriverObject );

	// Retrieve process offset in EPROCESS
	if( !GetProcessNameOffset() )
	{
		KdPrint(("Error getting process name offset!"));
		ntStatus = STATUS_UNSUCCESSFUL;
		IoDeleteSymbolicLink( &uDosDeviceName );
		IoDeleteDevice( pDriverObject->DeviceObject );
		return ntStatus;
	}

	// Retrieve kernel base pointer
	pStackAttach = (PVOID)&KeStackAttachProcess;
	g_pKrnlBase = KernelGetModuleBaseByPtr( pStackAttach, "KeStackAttachProcess" );
	if( !g_pKrnlBase )
	{
		KdPrint(("Error getting ntoskrnl base!"));
		ntStatus = STATUS_UNSUCCESSFUL;
		IoDeleteSymbolicLink( &uDosDeviceName );
		IoDeleteDevice( pDriverObject->DeviceObject );
		return ntStatus;
	}
	KdPrint((""__FUNCTION__" Kernel base: 0x%08x", g_pKrnlBase));

	// Retrieve kernel name (differs from system to system)
	if( !GetModuleNameByBase( g_pKrnlBase, szKernelName, NULL ) )
	{
		KdPrint(("Error getting kernel name by base"));
		ntStatus = STATUS_UNSUCCESSFUL;
		IoDeleteSymbolicLink( &uDosDeviceName );
		IoDeleteDevice( pDriverObject->DeviceObject );
		return ntStatus;
	}
	KdPrint((""__FUNCTION__" NT OS Kernel Name: %s", szKernelName));

	__try
	{
		KeEnterCriticalRegion( );
		if( !GetServiceDescriptorTableShadow(&KeServiceDescriptorTableShadow) )
		{
			KdPrint((""__FUNCTION__": Error on retrieving shadow table"));
			ntStatus = STATUS_UNSUCCESSFUL;
			IoDeleteSymbolicLink( &uDosDeviceName );
			IoDeleteDevice( pDriverObject->DeviceObject );
			return ntStatus;
		}
		KeLeaveCriticalRegion( );

		if( !bSetModuleHideHooks() )
		{
			KdPrint((""__FUNCTION__": Error initializing ModuleHide hooks"));
			ntStatus = STATUS_UNSUCCESSFUL;
			IoDeleteSymbolicLink( &uDosDeviceName );
			IoDeleteDevice( pDriverObject->DeviceObject );
			return ntStatus;
		}

		if( !BPInitializeHooks() )
		{
			KdPrint((""__FUNCTION__": Error initializing BPHide hooks"));
			ntStatus = STATUS_UNSUCCESSFUL;
			IoDeleteSymbolicLink( &uDosDeviceName );
			IoDeleteDevice( pDriverObject->DeviceObject );
			return ntStatus;
		}

		if( !ASInitializeHooks() )
		{
			KdPrint((""__FUNCTION__": Error initializing AntiScreenshot hooks"));
			ntStatus = STATUS_UNSUCCESSFUL;
			IoDeleteSymbolicLink( &uDosDeviceName );
			IoDeleteDevice( pDriverObject->DeviceObject );
			BPDestroyHooks( );
			return ntStatus;
		}

	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		KdPrint(("Exception in DriverLoad. Code: 0x%08x", GetExceptionCode()));
		IoDeleteSymbolicLink( &uDosDeviceName );
		IoDeleteDevice( pDriverObject->DeviceObject );
		BPDestroyHooks( );
		return STATUS_UNSUCCESSFUL;
	}

	return ntStatus;
}

NTSTATUS OnDispatch( IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp )
{
	PIO_STACK_LOCATION irpStack = NULL;
	PVOID ioBuffer = NULL;
	ULONG inputBufferLength = 0, outputBufferLength = 0;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	unsigned int iPresent = 1;
	int iScreenCounter = 0;
	BOOLEAN bIsSafe;
	cloak_args_t tCloakArgs;

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation( pIrp );
	switch( irpStack->MajorFunction )
	{
	case IRP_MJ_DEVICE_CONTROL:
		if( irpStack->Parameters.DeviceIoControl.IoControlCode ==
			IOCTL_XPROTECT_CHECK_PRESENCE )
		{
			outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

			if( outputBufferLength < sizeof(unsigned int) )
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				pIrp->IoStatus.Status = ntStatus;
				break;
			}
			ioBuffer = pIrp->AssociatedIrp.SystemBuffer;
			RtlCopyMemory( ioBuffer, &iPresent, sizeof(unsigned int) );
			pIrp->IoStatus.Information = sizeof(unsigned int);
		}
		else if( irpStack->Parameters.DeviceIoControl.IoControlCode ==
			IOCTL_XPROTECT_CLOAK_MODULE )
		{
			// HACK: We need the input buffer
			outputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

			if( outputBufferLength < sizeof(cloak_args_t) )
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				pIrp->IoStatus.Status = ntStatus;
				break;
			}
			ioBuffer = pIrp->AssociatedIrp.SystemBuffer;
			RtlCopyMemory( &tCloakArgs, ioBuffer, sizeof(cloak_args_t) );
			// TODO: Use calling process name
			bCloakModule( tCloakArgs.dwModuleBase, tCloakArgs.dwModuleSize, tCloakArgs.szProcessName );
			pIrp->IoStatus.Information = sizeof(cloak_args_t);
		}
		else if( irpStack->Parameters.DeviceIoControl.IoControlCode ==
			IOCTL_XPROTECT_GAMESTART )
		{
			// Called in HUD_Redraw of the Cheat
			g_bGameIsActive = TRUE;
			pIrp->IoStatus.Information = 1;
		}
		else if( irpStack->Parameters.DeviceIoControl.IoControlCode ==
			IOCTL_XPROTECT_SET_THREAD_CONTEXT )
		{
			// HACK: We need the input buffer
			outputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

			if( outputBufferLength < sizeof(set_thread_context_t) )
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				pIrp->IoStatus.Status = ntStatus;
				break;
			}
			ioBuffer = pIrp->AssociatedIrp.SystemBuffer;
			((set_thread_context_t*)ioBuffer)->bSuccess = (UINT)BPInitializeSpoofAndSetContext(
				((set_thread_context_t*)ioBuffer)->hThread,
				((set_thread_context_t*)ioBuffer)->pContext,
				(BOOLEAN)((set_thread_context_t*)ioBuffer)->bSpoofLock);
			RtlCopyMemory( ioBuffer, ioBuffer, sizeof(set_thread_context_t) ); // SHITNZ!
			pIrp->IoStatus.Information = ((set_thread_context_t*)ioBuffer)->bSuccess;
		}
		else if( irpStack->Parameters.DeviceIoControl.IoControlCode ==
			IOCTL_XPROTECT_IS_DRAWING_SAFE )
		{
			outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

			KeEnterCriticalRegion();
			if( g_bDrawingIsSafe )
			{
				bIsSafe = TRUE;
				g_bScreenIsSafe = FALSE;
				iScreenCounter = 0;
			}
			else
			{
				bIsSafe = FALSE;
				iScreenCounter++;
			}

			if( iScreenCounter >= 5 )
			{
				KdPrint(("Screen is safe"));
				g_bScreenIsSafe = TRUE; // Release block so Anti-Cheat can take screenshot, screen is now safe
			}
			KeLeaveCriticalRegion();

			if( outputBufferLength < sizeof(BOOLEAN) )
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				pIrp->IoStatus.Status = ntStatus;
				break;
			}
			ioBuffer = pIrp->AssociatedIrp.SystemBuffer;
			RtlCopyMemory( ioBuffer, &bIsSafe, sizeof(BOOLEAN) );
			pIrp->IoStatus.Information = sizeof(BOOLEAN);
		}
		break;
	default:
		break;
	}

	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return ntStatus;
}

VOID DriverUnload( IN PDRIVER_OBJECT pDriverObject )
{
	UNICODE_STRING uDosDevice;
	KdPrint(("Unloading driver"));

	// Remove hooks
	BPDestroyHooks( );
	ASDestroyHooks( );

	// Delete Device
	RtlInitUnicodeString( &uDosDevice, DosDeviceName );
	IoDeleteSymbolicLink( &uDosDevice );
	IoDeleteDevice( pDriverObject->DeviceObject );
}
