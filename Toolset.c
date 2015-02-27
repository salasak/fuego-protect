#include "Main.h"
#include "Toolset.h"

_declspec(naked) void CrashDriver( void )
{
	_asm
	{
		mov ebx, 0xDEADBEEF; 
		mov esp, 0xDEADBEEF;
		sub ebp, esp;
		mov bl, 0;
		div ebx;
		xor al, al;
		xor ecx, ecx;
		jmp ebx;
	}
}

BOOLEAN ModuleCheck( BYTE* pFunction, const char *pszModuleName, char *pszHookingModule )
{
	char szModule[512];
	BYTE bDetourCheck[2];

	// TODO: Extend detour check
	GetFunctionModuleLocation( pFunction, szModule );
	RtlCopyMemory( bDetourCheck, pFunction, sizeof(bDetourCheck) );

	if( !strcmp(pszModuleName, szModule) )
	{
		// Function is in the supposed module
		// now additionaly check for simple jmp detour
		if( bDetourCheck[0] == 0xE9 )
		{
			if( pszHookingModule != NULL )
				strcpy( pszHookingModule, "DETOUR_NO_MODULE" );
			return FALSE; // Function is detoured
		} 
		else
			return TRUE;
	}

	if( pszHookingModule != NULL )
		strcpy( pszHookingModule, szModule );

	return FALSE; // Function is not in the supposed module
}


/******************************************/
/* Function: GetServiceDescriptorTableShadow
/* Description: Locates the address of ServiceDescriptorTableShadow
/* Params: ppServiceTable - Will contain the shadow table on success 
or will point to NULL on failure
/* Return: FALSE on failure, TRUE on success
/******************************************/
BOOLEAN GetServiceDescriptorTableShadow( OUT PServiceDescriptorTableEntry_t *ppServiceTable )
{
	BYTE* p = (BYTE*)KeAddSystemServiceTable;
	ULONG uCount = 0;
	DWORD dwTable = 0;

	for( ; uCount < PAGE_SIZE; uCount++, p++ )
	{
		__try
		{
			dwTable = *(DWORD*)p;
			if( MmIsAddressValid((PVOID)dwTable) )
			{
				if( memcmp((PVOID)dwTable, &KeServiceDescriptorTable, 16) == 0 )
				{
					if( (PVOID)dwTable == &KeServiceDescriptorTable )
					{
						continue;
					}
					break;
				}
			}
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			dwTable = 0;
			break;
		}
	}

	if( dwTable != 0 )
	{
		*ppServiceTable = (PServiceDescriptorTableEntry_t)dwTable;
		return TRUE;
	}

	*ppServiceTable = NULL;
	return FALSE;
} 

BOOLEAN GetModuleNameByBase( IN PVOID pBase, OUT PCHAR pszModuleName, OUT OPTIONAL PDWORD pdwImageSize )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PSYSTEM_MODULE_INFORMATION pModuleInformation = NULL;
	ULONG uReturnLength = 0, uModuleInformationCount = 0, uCount = 0;
	PSYSTEM_MODULE_ENTRY pModule = NULL;
	DWORD dwImageSize = 0, dwImageBase = 0;
	unsigned int iStrLen = 0;
	char *pszImageName = NULL;
	DWORD dwCheckBase = (DWORD)pBase;

	if( !pBase || !pszModuleName )
		return FALSE;

	__try 
	{
		ntStatus = ZwQuerySystemInformation( SystemModuleInformation, (PVOID)&pModuleInformation, 0, 
			&uReturnLength );

		if( !uReturnLength )
		{
			KdPrint((""__FUNCTION__": Error obtaining return length"));
			return FALSE;
		} 

		pModuleInformation = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag( NonPagedPool, uReturnLength*2, 
			'SMI1' );
		if( !pModuleInformation )
		{
			KdPrint((""__FUNCTION__": Error allocating memory for SystemModuleInformation"));
			return FALSE;
		}

		RtlZeroMemory( pModuleInformation, uReturnLength*2 );
		ntStatus = ZwQuerySystemInformation( SystemModuleInformation, (PVOID)pModuleInformation, uReturnLength*2,
			&uReturnLength );
		if( !NT_SUCCESS(ntStatus) )
		{
			KdPrint((""__FUNCTION__": Error on ZwQuerySystemInformation"));
			return FALSE;
		}

		pModule = ( (PSYSTEM_MODULE_INFORMATION)(pModuleInformation) )->Module;
		for( ; uCount < ( (PSYSTEM_MODULE_INFORMATION)(pModuleInformation) )->Count; uCount++ )
		{
			dwImageSize = pModule[uCount].ModuleSize;
			dwImageBase = (DWORD)pModule[uCount].ModuleBaseAddress;
			if( dwCheckBase == dwImageBase )
			{
				pszImageName = (char*)pModule[uCount].ModuleName+pModule[uCount].ModuleNameOffset;
				iStrLen = strlen(pszImageName);
				strncpy( pszModuleName, pszImageName, iStrLen );
				pszModuleName[iStrLen] = '\0';
				ExFreePoolWithTag( pModuleInformation, 'SMI1' );
				if( pdwImageSize != NULL )
				{
					*pdwImageSize = dwImageSize;
				}
				return TRUE;
			}
		}

		// Module not found
		iStrLen = strlen("unknown_module");
		strncpy( pszModuleName, "unknown_module", iStrLen );
		pszModuleName[iStrLen] = '\0';
		ExFreePoolWithTag( pModuleInformation, 'SMI1' );
		return TRUE;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		if( pModuleInformation )
			ExFreePoolWithTag( pModuleInformation, 'SMI1' );
		return FALSE;
	}
}

/******************************************/
/* Function: GetFunctionModuleLocation
/* Description: Gets module in which a function is stored and stores its' name
or unknown_module if not found.
/* Params: pFunction - Pointer to the variable/function to scan for
pszModuleName - Module name will be stored in
/* Return: FALSE on failure, TRUE on success
/******************************************/
BOOLEAN GetFunctionModuleLocation( IN PVOID pFunction, OUT PCHAR pszModuleName )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PSYSTEM_MODULE_INFORMATION pModuleInformation = NULL;
	ULONG uReturnLength = 0, uModuleInformationCount = 0, uCount = 0;
	PSYSTEM_MODULE_ENTRY pModule = NULL;
	DWORD dwImageSize = 0, dwImageBase = 0;
	DWORD dwFunction = 0;
	unsigned int iStrLen = 0;
	char *pszImageName = NULL;

	if( !pFunction || !pszModuleName )
		return FALSE;

	__try 
	{
		dwFunction = (DWORD)pFunction;
		ntStatus = ZwQuerySystemInformation( SystemModuleInformation, (PVOID)&pModuleInformation, 0, 
			&uReturnLength );

		if( !uReturnLength )
		{
			KdPrint((""__FUNCTION__": Error obtaining return length"));
			return FALSE;
		} 

		pModuleInformation = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag( NonPagedPool, uReturnLength*2, 
			'SMI1' );
		if( !pModuleInformation )
		{
			KdPrint((""__FUNCTION__": Error allocating memory for SystemModuleInformation"));
			return FALSE;
		}

		RtlZeroMemory( pModuleInformation, uReturnLength*2 );
		ntStatus = ZwQuerySystemInformation( SystemModuleInformation, (PVOID)pModuleInformation, uReturnLength*2,
			&uReturnLength );
		if( !NT_SUCCESS(ntStatus) )
		{
			KdPrint((""__FUNCTION__": Error on ZwQuerySystemInformation"));
			return FALSE;
		}

		pModule = ( (PSYSTEM_MODULE_INFORMATION)(pModuleInformation) )->Module;
		for( ; uCount < ( (PSYSTEM_MODULE_INFORMATION)(pModuleInformation) )->Count; uCount++ )
		{
			dwImageSize = pModule[uCount].ModuleSize;
			dwImageBase = (DWORD)pModule[uCount].ModuleBaseAddress;
			if( (dwFunction >= dwImageBase) && (dwFunction <= dwImageBase+dwImageSize) )
			{
				// Function lies in module range
				pszImageName = (char*)pModule[uCount].ModuleName+pModule[uCount].ModuleNameOffset;
				iStrLen = strlen(pszImageName);
				strncpy( pszModuleName, pszImageName, iStrLen );
				pszModuleName[iStrLen] = '\0';
				ExFreePoolWithTag( pModuleInformation, 'SMI1' );
				return TRUE;
			}
		}

		// Module not found
		iStrLen = strlen("unknown_module");
		strncpy( pszModuleName, "unknown_module", iStrLen );
		pszModuleName[iStrLen] = '\0';
		ExFreePoolWithTag( pModuleInformation, 'SMI1' );
		return TRUE;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		if( pModuleInformation )
			ExFreePoolWithTag( pModuleInformation, 'SMI1' );
		return FALSE;
	}
}

/******************************************/
/* Function: KernelGetModuleBaseByPtr
/* Description: Gets base address of a module by a exported variable or function
/* Params: ptrInSection - Pointer to the variable/function
ptrExportedName - Name of the variable/function
/* Return: NULL on failure, Base address on success 
/******************************************/
PVOID KernelGetModuleBaseByPtr( IN PVOID ptrInSection, IN PCHAR ptrExportedName )
{
	PUCHAR p;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;
	DWORD dwExportedAddr = 0;

	p = (PUCHAR)((ULONG)ptrInSection & ~(PAGE_SIZE-1));

	for(;p;p -= PAGE_SIZE) {
		__try
		{
			dos = (PIMAGE_DOS_HEADER)p;
			if(dos->e_magic != IMAGE_DOS_SIGNATURE) // MZ
				continue;

			nt = (PIMAGE_NT_HEADERS)((ULONG)dos + dos->e_lfanew);
			if((ULONG)nt >= (ULONG)ptrInSection)
				continue;
			if((ULONG)nt <= (ULONG)dos)
				continue;

			if(nt->Signature != IMAGE_NT_SIGNATURE) // PE
				continue;

			if(!ptrExportedName) {
				break;
			} else {
				ReadEAT( p, ptrExportedName, &dwExportedAddr );
				if((DWORD)ptrInSection == dwExportedAddr) {
					break;
				}
			}
			p = NULL;
			break;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			p = NULL;
			break;
		}
	}
	return p;
}

/******************************************/
/* Function: ReadEAT
/* Description: Gets the address of a function from the EAT of a speicifed module
/* Params: pBase - Base of the module to read from
pszFunction - Function name to scan for
pdwFunctionAddress - Function address will be stored in on success
/* Return: FALSE on failure, TRUE on success
/******************************************/
BOOLEAN ReadEAT( IN PVOID pBase, IN PCHAR pszFunction, OUT PULONG pdwFunctionAddress )
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS32 pNtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	ULONG *pdwAddressTable = NULL;
	PCHAR *pszNameTable = NULL;
	PWORD pwOrdinalTable = NULL;
	PCHAR pszName = NULL;
	ULONG uFunctionAddress = 0, lCount = 0, uSize = 0;

	if( !pszFunction || !pdwFunctionAddress || !MmIsAddressValid(pBase) )
	{
		KdPrint((""__FUNCTION__": Base address for EAT read is not valid or parameter validation failed"));
		return FALSE;
	} 

	__try 
	{ 
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData( pBase, TRUE, 0, &uSize );
		if( !pExportDirectory )
			return FALSE;

		pdwAddressTable = (ULONG*)( (ULONG)pBase+pExportDirectory->AddressOfFunctions );
		pszNameTable   = (PCHAR*)( (ULONG)pBase+pExportDirectory->AddressOfNames );
		pwOrdinalTable = (PWORD)( (ULONG)pBase+pExportDirectory->AddressOfNameOrdinals );

		for( lCount = 0; lCount < pExportDirectory->NumberOfFunctions; lCount++ )
		{
			pszName = (PCHAR)( (ULONG)pBase+pszNameTable[lCount] ); // RVA to VA

			if( !strcmp(pszName, pszFunction) )
			{
				uFunctionAddress = (ULONG)( (ULONG)pBase+pdwAddressTable[pwOrdinalTable[lCount]] );
				KdPrint((""__FUNCTION__": Found EAT function %s at 0x%08x", pszName, uFunctionAddress));
				*pdwFunctionAddress = uFunctionAddress;
				return TRUE;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		*pdwFunctionAddress = 0;
		return FALSE;
	}

	*pdwFunctionAddress = 0;
	KdPrint((""__FUNCTION__": No EAT function found"));
	return FALSE;
}

/******************************************/
/* Function: GetImageBaseFromName
/* Description: Gets the base of an memory image by name
/* Params: pszImage - Name of the image to scan for
pdwImageBase - On success, this will contain the image base
pdwImageSize - On success, this will contain the image size
/* Return: FALSE on failure, TRUE on success
/******************************************/
BOOLEAN GetImageBaseFromName( IN PCHAR pszImage, OUT PULONG pdwImageBase, OUT OPTIONAL PULONG pdwImageSize )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PSYSTEM_MODULE_INFORMATION pModuleInformation = NULL;
	ULONG uReturnLength = 0, uModuleInformationCount = 0, uCount = 0;
	PSYSTEM_MODULE_ENTRY pModule = NULL;

	__try 
	{
		ntStatus = ZwQuerySystemInformation( SystemModuleInformation, (PVOID)&pModuleInformation, 0, 
			&uReturnLength );

		if( !uReturnLength )
		{
			KdPrint((""__FUNCTION__": Error obtaining return length"));
			return FALSE;
		} 

		pModuleInformation = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag( NonPagedPool, uReturnLength*2, 
			'SMI1' );
		if( !pModuleInformation )
		{
			KdPrint((""__FUNCTION__": Error allocating memory for SystemModuleInformation"));
			return FALSE;
		}

		RtlZeroMemory( pModuleInformation, uReturnLength*2 );
		ntStatus = ZwQuerySystemInformation( SystemModuleInformation, (PVOID)pModuleInformation, uReturnLength*2,
			&uReturnLength );
		if( !NT_SUCCESS(ntStatus) )
		{
			KdPrint((""__FUNCTION__": Error on ZwQuerySystemInformation"));
			return FALSE;
		}

		pModule = ( (PSYSTEM_MODULE_INFORMATION)(pModuleInformation) )->Module;
		for( ; uCount < ( (PSYSTEM_MODULE_INFORMATION)(pModuleInformation) )->Count; uCount++ )
		{
			if( !_stricmp((char*)pModule[uCount].ModuleName+pModule[uCount].ModuleNameOffset, pszImage) )
			{
				KdPrint(("Found module %s", pszImage));
				*pdwImageBase = (ULONG)pModule[uCount].ModuleBaseAddress;
				if( pdwImageSize != NULL )
					*pdwImageSize = pModule[uCount].ModuleSize;
				ExFreePoolWithTag( pModuleInformation, 'SMI1' );
				return TRUE;
			}
		}

		ExFreePoolWithTag( pModuleInformation, 'SMI1' );
		return FALSE; // Module not found
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		if( pModuleInformation )
			ExFreePoolWithTag( pModuleInformation, 'SMI1' );
		return FALSE;
	}
}