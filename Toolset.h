#ifndef __TOOL__H
#define __TOOL__H

typedef struct ServiceDescriptorEntry 
{
	PVOID *ServiceTable;
	ULONG *ServiceCounterTableBase;
	ULONG NumberOfServices;
	UCHAR *ParamTable;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	ServiceDescriptorTableEntry_t ntoskrnl; //SST used by ntoskrnl.exe - Native API
	ServiceDescriptorTableEntry_t win32k; // SST used by win32k.sys - gdi/user support
	ServiceDescriptorTableEntry_t Table3; // reserved
	ServiceDescriptorTableEntry_t Table4; // reserved
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE, **PPSERVICE_DESCRIPTOR_TABLE;

NTSYSAPI ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
NTSYSAPI _stdcall KeAddSystemServiceTable(PVOID, PVOID, PVOID, PVOID, PVOID);

PVOID KernelGetModuleBaseByPtr( IN PVOID ptrInSection, IN PCHAR ptrExportedName );
BOOLEAN GetImageBaseFromName( IN PCHAR pszImage, OUT PULONG pdwImageBase, OUT OPTIONAL PULONG pdwImageSize );
BOOLEAN ReadEAT( IN PVOID pBase, IN PCHAR pszFunction, OUT PULONG pdwFunctionAddress );
BOOLEAN GetFunctionModuleLocation( IN PVOID pFunction, OUT PCHAR pszModuleName );
BOOLEAN GetServiceDescriptorTableShadow( OUT PServiceDescriptorTableEntry_t *ppServiceTable );
BOOLEAN ModuleCheck( BYTE* pFunction, const char *pszModuleName, char *pszHookingModule );
BOOLEAN GetModuleNameByBase( IN PVOID pBase, OUT PCHAR pszModuleName, OUT OPTIONAL PDWORD pdwImageSize );

extern void CrashDriver( void );

#endif 