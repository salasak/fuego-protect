#include "Main.h"
#include "Toolset.h"
#include "Detour.h"
#include "ModuleHide.h"

static DWORD m_dwModuleBase;
static DWORD m_dwModuleSize;
static char m_szProcessName[256];
static BOOLEAN m_bCloaking = FALSE;

NtReadVirtualMemory_t ogNtReadVirtualMemory = NULL;
NtQueryVirtualMemory_t ogNtQueryVirtualMemory = NULL;
DetourObject_t* dtNtReadVirtualMemory = NULL;
DetourObject_t* dtNtQueryVirtualMemory = NULL;

// This could be improved...

NTSTATUS NTAPI hkNtQueryVirtualMemory(	IN HANDLE   	 ProcessHandle,
										IN PVOID  	Address,
										IN MEMORY_INFORMATION_CLASS VirtualMemoryInformationClass,
										OUT PVOID  	VirtualMemoryInformation,
										IN SIZE_T  	Length,
										OUT PSIZE_T  	ResultLength
									 )
{
	NTSTATUS Result;
	NTSTATUS Status;
	PEPROCESS Process = NULL;
	PMEMORY_BASIC_INFORMATION pInformation;
	MEMORY_BASIC_INFORMATION nextBlock;
	DWORD dwBaseAddress = 0;
	SIZE_T ResultLen;
	char szName[256];

	Result = ogNtQueryVirtualMemory( ProcessHandle, Address, VirtualMemoryInformationClass, VirtualMemoryInformation, Length, ResultLength );
	pInformation = (PMEMORY_BASIC_INFORMATION)VirtualMemoryInformation;

	if( !m_bCloaking )
		return Result;

	Status = ObReferenceObjectByHandle( ProcessHandle,
		0x0400 /*PROCESS_QUERY_INFORMATION*/,
		*PsProcessType,
		ExGetPreviousMode(),
		(PVOID*)&Process,
		NULL );
	if( !NT_SUCCESS(Status) )
		return Result;

	GetProcessName( szName, Process );
	if( Result > 0 && VirtualMemoryInformationClass == MemoryBasicInformation &&
		!strcmp(szName, m_szProcessName) )
	{
		KdPrint(("Cloaking NtQueryVirtualMemory call"));
		RtlZeroMemory( &nextBlock, sizeof(MEMORY_BASIC_INFORMATION) );
		ogNtQueryVirtualMemory( ProcessHandle, Address, VirtualMemoryInformationClass, (PVOID)&nextBlock,
			sizeof(MEMORY_BASIC_INFORMATION), &ResultLen );

		dwBaseAddress = (DWORD)Address;
		if( dwBaseAddress >=  m_dwModuleBase &&
			dwBaseAddress <= m_dwModuleBase+m_dwModuleSize )
		{
			// This is the block to stealth
			pInformation->AllocationBase = NULL;
			pInformation->AllocationProtect = 0;
			pInformation->State = MEM_FREE;
			pInformation->Protect = PAGE_NOACCESS;
			pInformation->Type = 0;

			// Next block is free too, merge them
			if( nextBlock.State == MEM_FREE )
				pInformation->RegionSize += nextBlock.RegionSize;
		}

		// Check if this block is MEM_FREE and following is the stealth block
		dwBaseAddress = (DWORD)pInformation->BaseAddress+pInformation->RegionSize;
		if( dwBaseAddress >= m_dwModuleBase &&
			dwBaseAddress <= m_dwModuleBase+m_dwModuleSize &&
			pInformation->State == MEM_FREE )
		{
			// Add the size of stealth block to this
			pInformation->RegionSize += m_dwModuleSize;

			// Next block is free too, merge them
			if( nextBlock.State == MEM_FREE )
				pInformation->RegionSize += nextBlock.RegionSize;

		}
	}
	ObDereferenceObject(Process);
	return Result;
}

NTSTATUS NTAPI hkNtReadVirtualMemory(	IN HANDLE   	 ProcessHandle,
										IN PVOID  	BaseAddress,
										OUT PVOID  	Buffer,
										IN SIZE_T  	NumberOfBytesToRead,
										OUT PSIZE_T  	NumberOfBytesRead
									)
{
	PEPROCESS Process = NULL;
	NTSTATUS Status;
	char szName[256];
	DWORD dwBaseAddress = (DWORD)BaseAddress;

	if( m_bCloaking )
	{
		Status = ObReferenceObjectByHandle( ProcessHandle,
											0x0010 /* PROCESS_VM_READ */ ,
											*PsProcessType,
											ExGetPreviousMode(),
											(PVOID*)&Process,
											NULL );
		if( NT_SUCCESS(Status) && Process )
		{
			GetProcessName( szName, Process );
			if( !strcmp(szName, m_szProcessName) )
			{
				if( dwBaseAddress >= m_dwModuleBase &&
					dwBaseAddress <= m_dwModuleBase+m_dwModuleSize )
				{
					KdPrint(("Cloaking RPM call to module"));
					ObDereferenceObject(Process);
					return STATUS_UNSUCCESSFUL;
				}

			}

			ObDereferenceObject(Process);
		}
	}

	return ogNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}


BOOLEAN bCloakModule( DWORD dwBaseAddress, DWORD dwSize, char* szProcessName )
{
	m_dwModuleBase = dwBaseAddress;
	m_dwModuleSize = dwSize;
	strcpy(m_szProcessName, szProcessName);
	m_bCloaking = TRUE;
	return m_bCloaking;
}

BOOLEAN bSetModuleHideHooks( VOID )
{
	DWORD dwNtReadVirtualMemoryAddr = 0, dwNtQueryVirtualMemoryAddr = 0;
	DWORD dwNtReadVirtualMemoryIndex, dwNtQueryVirtualMemoryIndex;
	RTL_OSVERSIONINFOW tVersion;

	tVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	if( !NT_SUCCESS(RtlGetVersion(&tVersion)) )
	{
		KdPrint((""__FUNCTION__": Error getting version"));
		return FALSE;
	}

	if( tVersion.dwMajorVersion == 5 && tVersion.dwMinorVersion == 1 )
	{
		// XP (SP3)
		dwNtReadVirtualMemoryIndex = 0x0BA;
		dwNtQueryVirtualMemoryIndex = 0x0B2;
	}
	else if( tVersion.dwMajorVersion == 6 && tVersion.dwMinorVersion == 0 )
	{
		// Vista (SP2)
		dwNtReadVirtualMemoryIndex = 0x105;
		dwNtQueryVirtualMemoryIndex = 0x0fd;
	}
	else if( tVersion.dwMajorVersion == 6 && tVersion.dwMinorVersion == 1 ) // Win 7
		return FALSE;

	dwNtReadVirtualMemoryAddr = (DWORD)KeServiceDescriptorTable.ServiceTable[dwNtReadVirtualMemoryIndex];
	dwNtQueryVirtualMemoryAddr = (DWORD)KeServiceDescriptorTable.ServiceTable[dwNtQueryVirtualMemoryIndex];

	dtNtReadVirtualMemory = DtCreateDetour( dwNtReadVirtualMemoryAddr, (ULONG)hkNtReadVirtualMemory );
	if( !dtNtReadVirtualMemory )
	{
		KdPrint(("Error detouring NtReadVirtualMemory"));
		return FALSE;
	}
	ogNtReadVirtualMemory = (NtReadVirtualMemory_t)dtNtReadVirtualMemory->Trampoline;

	dtNtQueryVirtualMemory = DtCreateDetour( dwNtQueryVirtualMemoryAddr, (ULONG)hkNtQueryVirtualMemory );
	if( !dtNtQueryVirtualMemory )
	{
		KdPrint(("Error detoruing NtQueryVirtualMemory"));
		return FALSE;
	}
	ogNtQueryVirtualMemory =  (NtQueryVirtualMemory_t)dtNtQueryVirtualMemory->Trampoline;


	return TRUE;
}
