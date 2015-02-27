#ifndef __MODULEHIDE__H_
#define __MODULEHIDE__H_

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_BASIC_INFORMATION
{
	PVOID BaseAddress;
	PVOID AllocationBase;
	ULONG AllocationProtect;
	SIZE_T RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} MEMORY_BASIC_INFORMATION,*PMEMORY_BASIC_INFORMATION;



typedef NTSTATUS(NTAPI *NtReadVirtualMemory_t)(IN HANDLE   	 ProcessHandle,
											   IN PVOID  	BaseAddress,
											   OUT PVOID  	Buffer,
											   IN SIZE_T  	NumberOfBytesToRead,
											   OUT PSIZE_T  	NumberOfBytesRead);
typedef NTSTATUS(NTAPI *NtQueryVirtualMemory_t)(IN HANDLE   	 ProcessHandle,
												IN PVOID  	Address,
												IN MEMORY_INFORMATION_CLASS VirtualMemoryInformationClass,
												OUT PVOID  	VirtualMemoryInformation,
												IN SIZE_T  	Length,
												OUT PSIZE_T  	ResultLength);

BOOLEAN bCloakModule( DWORD dwBaseAddress, DWORD dwSize, char* szProcessName );
BOOLEAN bSetModuleHideHooks( VOID );

#endif
