#include "Main.h"
#include "Toolset.h"
#include "Detour.h"

// Global declarations
typedef NTSTATUS (NTAPI *NtQueryValueKey_t)( IN HANDLE KeyHandle, 
											IN PUNICODE_STRING ValueName, 
											IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, 
											OUT PVOID KeyValueInformation, 
											IN ULONG Length, 
											OUT PULONG ResultLength );
typedef NTSTATUS (NTAPI *NtOpenKey_t)( OUT PHANDLE pKeyHandle, 
									  IN ACCESS_MASK DesiredAccess, 
									  IN POBJECT_ATTRIBUTES ObjectAttributes );


NtQueryValueKey_t ogNtQueryValueKey = NULL;
NtOpenKey_t ogNtOpenKey = NULL;

DetourObject_t* dtNtQueryValueKey = NULL;
DetourObject_t* dtNtOpenKey = NULL;

NTSTATUS
NTAPI
hkNtOpenKey( OUT PHANDLE pKeyHandle, 
		  IN ACCESS_MASK DesiredAccess, 
		  IN POBJECT_ATTRIBUTES ObjectAttributes )
{
	char szProcessName[32];
	GetProcessName( szProcessName, PsGetCurrentProcess() );
	if( !strcmp(szProcessName, "SGLAC.exe") )
	{
		//KdPrint(("OpenKey: 0x%08x %wZ", *pKeyHandle, ObjectAttributes->ObjectName));
	}
	return ogNtOpenKey(pKeyHandle, DesiredAccess, ObjectAttributes);
}
 
NTSTATUS
NTAPI
hkNtQueryValueKey( IN HANDLE KeyHandle, 
				IN PUNICODE_STRING ValueName, 
				IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, 
				OUT PVOID KeyValueInformation, 
				IN ULONG Length, 
				OUT PULONG ResultLength )
{
	char szProcessName[32];
	ULONG NameOffset;
	ULONG NameSizeOffset;
	PULONG KeyNameLength;
	WCHAR* KeyNamePtr;
	PBYTE key = (PBYTE)KeyValueInformation;

	NTSTATUS ntReturn = ogNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	wchar_t wszNewIdentifier[] = L"x86 Family 12 Model 2 Stepping 3\0";
	GetProcessName( szProcessName, PsGetCurrentProcess() );

	if( !strcmp(szProcessName, "SGLAC.exe") )
	{
		switch( KeyValueInformationClass )
		{   
		case KeyValueBasicInformation:
			NameOffset = ((ULONG)&(((PKEY_VALUE_BASIC_INFORMATION)key)->Name)) - ((ULONG)key);
			NameSizeOffset = ((ULONG)&(((PKEY_VALUE_BASIC_INFORMATION)key)->NameLength)) 
				- ((ULONG)key);                  
			break;

		case KeyValueFullInformation:
			NameOffset = ((ULONG)&(((PKEY_VALUE_FULL_INFORMATION)key)->Name)) - ((ULONG)key);
			NameSizeOffset = ((ULONG)&(((PKEY_VALUE_FULL_INFORMATION)key)->NameLength)) 
				- ((ULONG)key);                             
			break;                                  
		case KeyValuePartialInformation:
			NameOffset = ((ULONG)&(((PKEY_VALUE_PARTIAL_INFORMATION)key)->Data)) - ((ULONG)key);
			NameSizeOffset = ((ULONG)&(((PKEY_VALUE_PARTIAL_INFORMATION)key)->DataLength)) 
				- ((ULONG)key);    
		}   

		KeyNamePtr = (WCHAR*)((PBYTE)key + NameOffset);
		KeyNameLength = (PULONG) ((PBYTE)key + NameSizeOffset);  
		KdPrint(("QueryValueKey: 0x%08x %wZ %ws", KeyHandle, ValueName, KeyNamePtr));

		//if( !wcscmp(ValueName->Buffer, L"Identifier") )
		//{
		//	KdPrint(("Found Identifier...changing!"));
		//	__try
		//	{
		//		*KeyNameLength = (ULONG)wcslen(wszNewIdentifier);
		//		wcscpy(KeyNamePtr, wszNewIdentifier);
		//	}
		//	__except(EXCEPTION_EXECUTE_HANDLER)
		//	{
		//		KdPrint(("Error changing identifier!"));
		//		return STATUS_UNSUCCESSFUL;
		//	}
		//}
	}
	return ntReturn;
}

BOOLEAN TestHook( void )
{
//	DWORD dwNtOpenKey = 0, dwNtQueryValueKey = 0;
//#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
//	dwNtOpenKey = (DWORD)KeServiceDescriptorTable.ServiceTable[SYSCALL_INDEX(ZwOpenKey)];
//	dwNtQueryValueKey = (DWORD)KeServiceDescriptorTable.ServiceTable[SYSCALL_INDEX(ZwQueryValueKey)];
//
//	KdPrint(("NtOpenKey: 0x%08x NtQueryValueKey: 0x%08x", dwNtOpenKey, dwNtQueryValueKey));
//
//	dtNtOpenKey = DtCreateDetour( dwNtOpenKey, (ULONG)hkNtOpenKey );
//	dtNtQueryValueKey = DtCreateDetour( dwNtQueryValueKey, (ULONG)hkNtQueryValueKey );
//	if( !dtNtOpenKey || !dtNtQueryValueKey )
//		return FALSE;
//
//	ogNtOpenKey = (NtOpenKey_t)dtNtOpenKey->Trampoline;
//	ogNtQueryValueKey = (NtQueryValueKey_t)dtNtQueryValueKey->Trampoline;
	return TRUE;
}

