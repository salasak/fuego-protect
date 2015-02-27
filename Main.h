#ifndef __MAIN__H_
#define __MAIN__H_

#include <ntddk.h>
#include <wdm.h>
#include "ntapi.h"

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE  0x00004550

#define ABSOLUTE(wait) (wait)
#define RELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos) \
	(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) \
	(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) \
	(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) \
	(((signed __int64)(seconds)) * MILLISECONDS(1000L))

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation, // Result is OBJECT_BASIC_INFORMATION structure
	ObjectNameInformation, // Result is OBJECT_NAME_INFORMATION structure
	ObjectTypeInformation, // Result is OBJECT_TYPE_INFORMATION structure
	ObjectAllInformation, // Result is OBJECT_ALL_INFORMATION structure
	ObjectDataInformation // Result is OBJECT_DATA_INFORMATION structure
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

#define SystemHandleInformation 0x10

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef unsigned char BYTE;
typedef ULONG DWORD;
typedef INT BOOL;
typedef UCHAR BYTE;
typedef USHORT WORD;
typedef BYTE *PBYTE;
typedef DWORD *PDWORD;
typedef BOOL *PBOOL;
typedef WORD *PWORD;

typedef struct _MODULE_ENTRY
{
	LIST_ENTRY le_mod;
	ULONG  unknown[4];
	ULONG  base;
	ULONG  driver_start;
	ULONG  unk1;
	UNICODE_STRING driver_Path;
	UNICODE_STRING driver_Name;
} MODULE_ENTRY, *PMODULE_ENTRY;

#pragma pack(push, 2)

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#pragma pack(pop)

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct cloak_args_s
{
	DWORD dwModuleBase;
	DWORD dwModuleSize;
	char szProcessName[256];
}cloak_args_t;

typedef struct set_thread_context_s
{
	HANDLE hThread;
	CONTEXT* pContext;
	unsigned int bSpoofLock;
	unsigned int bSuccess;
}set_thread_context_t;


#define FILE_DEVICE_XPROTECT 0x00002a8d
#define IOCTL_XPROTECT_GAMESTART (ULONG)CTL_CODE(FILE_DEVICE_XPROTECT, 0x01, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_XPROTECT_CHECK_PRESENCE (ULONG)CTL_CODE(FILE_DEVICE_XPROTECT, 0x02, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_XPROTECT_IS_DRAWING_SAFE (ULONG)CTL_CODE(FILE_DEVICE_XPROTECT, 0x03, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_XPROTECT_SET_THREAD_CONTEXT (ULONG)CTL_CODE(FILE_DEVICE_XPROTECT, 0x04, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_XPROTECT_CLOAK_MODULE (ULONG)CTL_CODE(FILE_DEVICE_XPROTECT, 0x05, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#include "Toolset.h" // HACK: Needed for PServiceDescriptorTableEntry_t
BOOLEAN GetProcessName( OUT PCHAR pszName, IN PEPROCESS peProcess );
extern PVOID g_pKrnlBase;
extern 	char szKernelName[256];
extern PServiceDescriptorTableEntry_t KeServiceDescriptorTableShadow;

#endif
