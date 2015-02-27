#include "Main.h"
#include "Toolset.h"
#include "Detour.h"
#include "AntiScreenshot.h"

// Global declarations
BOOLEAN g_bDrawingIsSafe = TRUE;
BOOLEAN g_bScreenIsSafe = FALSE;
BOOLEAN g_bGameIsActive = FALSE;

static 	PEPROCESS peCrs = NULL;

NtGdiGetPixel_t ogNtGdiGetPixel = NULL;
NtGdiCreateCompatibleBitmap_t ogNtGdiCreateCompatibleBitmap = NULL;

DetourObject_t* dtNtGdiGetPixel = NULL;
DetourObject_t* dtNtGdiCreateCompatibleBitmap = NULL;
VOID CreateProcessNotify( IN HANDLE ParentId, IN HANDLE ProcessId, IN BOOLEAN Create )
{
	PEPROCESS theProcess;
	char szProcessName[32];

	if( !NT_SUCCESS(PsLookupProcessByProcessId( (PVOID)ProcessId, &theProcess )) )
	{
		KdPrint((""__FUNCTION__": Error looking up EPROCESS"));
		return;
	}
	GetProcessName(szProcessName, theProcess);
	if( !strcmp(szProcessName, "hl.exe") )
	{
		if( !Create ) // Don't block screenshots anymore, cheat is unloaded
		{
			KdPrint((""__FUNCTION__": Half-Life closed"));
			KeEnterCriticalRegion();
			g_bGameIsActive = FALSE;
			KeLeaveCriticalRegion();
		}
	}
	ObDereferenceObject(theProcess);
}

void BlockUntilScreenIsSafe( void )
{
	LARGE_INTEGER Sleep;

	Sleep.QuadPart = RELATIVE(MILLISECONDS(20));
	g_bDrawingIsSafe = FALSE;
	while( TRUE )
	{
		if( g_bScreenIsSafe || !g_bGameIsActive )
			break;
		KeDelayExecutionThread( KernelMode, FALSE, &Sleep );
	}
	g_bDrawingIsSafe = TRUE;
}

void ReleaseBlock( void )
{
	//KeEnterCriticalRegion();
	//g_bDrawingIsSafe = TRUE;
	//KeLeaveCriticalRegion();
}

PVOID GetInfoTable(ULONG ATableType)
{
	ULONG mSize = 0x4000;
	PVOID mPtr = NULL;
	NTSTATUS St;
	do
	{
		mPtr = ExAllocatePool(PagedPool, mSize);
		memset(mPtr, 0, mSize);
		if (mPtr)
		{
			St = ZwQuerySystemInformation(ATableType, mPtr, mSize, NULL);
		} else return NULL;
		if (St == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(mPtr);
			mSize = mSize * 2;
		}
	} while (St == STATUS_INFO_LENGTH_MISMATCH);
	if (St == STATUS_SUCCESS) return mPtr;
	ExFreePool(mPtr);
	return NULL;
}

HANDLE GetCsrPid()
{
	HANDLE Process, hObject;
	HANDLE CsrId = (HANDLE)0;
	OBJECT_ATTRIBUTES obj;
	CLIENT_ID cid;
	UCHAR Buff[0x100];
	POBJECT_NAME_INFORMATION ObjName = (PVOID)&Buff;
	PSYSTEM_HANDLE_INFORMATION_EX Handles;
	ULONG r;

	Handles = GetInfoTable(SystemHandleInformation);

	if (!Handles) return CsrId;

	for (r = 0; r < Handles->NumberOfHandles; r++)
	{
		if (Handles->Information[r].ObjectTypeNumber == 21) //Port object
		{
			InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

			cid.UniqueProcess = (HANDLE)Handles->Information[r].ProcessId;
			cid.UniqueThread = 0;

			if (NT_SUCCESS(NtOpenProcess(&Process, PROCESS_DUP_HANDLE, &obj, &cid)))
			{
				if (NT_SUCCESS(ZwDuplicateObject(Process, (HANDLE)Handles->Information[r].Handle,NtCurrentProcess(), &hObject, 0, 0, DUPLICATE_SAME_ACCESS)))
				{
					if (NT_SUCCESS(ZwQueryObject(hObject, ObjectNameInformation, ObjName, 0x100, NULL)))
					{
						if (ObjName->Name.Buffer && !wcsncmp(L"\\Windows\\ApiPort", ObjName->Name.Buffer, 20))
						{
							CsrId = (HANDLE)Handles->Information[r].ProcessId;
						}
					}

					ZwClose(hObject);
				}

				ZwClose(Process);
			}
		}
	}

	ExFreePool(Handles);
	return CsrId;
}

// This works for every A-C that uses GDI to take screenshots
// Other ways of taking Screenshots:
// glReadPixel
// DirectX
// Call the internal screenshot function of the game
HBITMAP NTAPI hkNtGdiCreateCompatibleBitmap( HDC hdc, INT cx, INT cy )
{
	char szProcess[32];
#ifdef _DEBUG
	GetProcessName(szProcess, PsGetCurrentProcess());
#endif

	//if( !strcmp(szProcess, "SGLAC.exe") || !strcmp(szProcess, "aequitas.exe") )
	//{
		if( g_bGameIsActive == TRUE )
		{
			KdPrint(("Blocking call until screen is safe"));
			BlockUntilScreenIsSafe(); // Wait for the cheat to deactivate its' visuals
			KdPrint(("Releasing call"));
		}
	//}
	return ogNtGdiCreateCompatibleBitmap(hdc, cx, cy);
}

DWORD NTAPI hkNtGdiGetPixel( IN HDC hdc, IN INT x, IN INT y )
{
	char szProcess[32];
	BOOL bReturn;

#ifdef _DEBUG
	GetProcessName(szProcess, PsGetCurrentProcess());
#endif
	//if( (!strcmp(szProcess, "aequitas.exe") || !strcmp(szProcess, "SGLAC.exe")) )
	//{

	if( g_bGameIsActive == TRUE )
	{
		KdPrint(("ntGdiGetPixel call from Anti-Cheat (%s)", szProcess));
		BlockUntilScreenIsSafe();
		bReturn = ogNtGdiGetPixel(hdc, x, y);
		ReleaseBlock();
	}
	//}
	//else
	//	return ogNtGdiGetPixel(hdc, x, y);

	return bReturn;
}

BOOLEAN ASInitializeHooks( void )
{
	NTSTATUS ntStatus;
	ULONG uPid = (ULONG)GetCsrPid();
	KAPC_STATE ApcState;
	DWORD dwW32kBase = 0;
	DWORD dwGdiGetPixel = 0, dwGdiCreateCompatibleBitmap = 0;
	RTL_OSVERSIONINFOW tVersion;
	DWORD dwGdiCreateCompatibleBitmapIndex, dwGdiGetPixelIndex;

	KdPrint(("csrss.exe: %d", uPid));
	ntStatus = PsLookupProcessByProcessId((PVOID)uPid, &peCrs);
	if( !NT_SUCCESS( ntStatus ))
	{
		KdPrint(("Looking up CRSS failed..."));
		return FALSE;;
	}

	tVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	if( !NT_SUCCESS(RtlGetVersion(&tVersion)) )
	{
		KdPrint((""__FUNCTION__": Error getting version"));
		return FALSE;
	}

	// TODO: Use dynamic method to get offsets
	// TODO: Use stealth ssdt hooking
	if( tVersion.dwMajorVersion == 5 && tVersion.dwMinorVersion == 1 )
	{
		// XP
		dwGdiGetPixelIndex = 0x0BF;
		dwGdiCreateCompatibleBitmapIndex = 0x01D;
	}
	else if( tVersion.dwMajorVersion == 6 && tVersion.dwMinorVersion == 0 )
	{
		// Vista
		dwGdiGetPixelIndex = 0x0C6;
		dwGdiCreateCompatibleBitmapIndex = 0x101E;
	}
	else if( tVersion.dwMajorVersion == 6 && tVersion.dwMinorVersion == 1 ) // Win 7
		return FALSE;

	KeStackAttachProcess( (PKPROCESS)peCrs, &ApcState );
	__try{
	dwGdiGetPixel = (DWORD)KeServiceDescriptorTableShadow[1].ServiceTable[dwGdiGetPixelIndex];
	dwGdiCreateCompatibleBitmap = (DWORD)KeServiceDescriptorTableShadow[1].ServiceTable[dwGdiCreateCompatibleBitmapIndex];

	dtNtGdiGetPixel = DtCreateDetour( dwGdiGetPixel, (DWORD)hkNtGdiGetPixel );
	if( !dtNtGdiGetPixel )
	{
		KdPrint(("Error detouring NtGdiGetPixel"));
		return FALSE;
	}
	ogNtGdiGetPixel = (NtGdiGetPixel_t)dtNtGdiGetPixel->Trampoline;

	dtNtGdiCreateCompatibleBitmap = DtCreateDetour( dwGdiCreateCompatibleBitmap, (DWORD)hkNtGdiCreateCompatibleBitmap );
	if( !dtNtGdiCreateCompatibleBitmap )
	{
		KdPrint(("Error detouring NtGdiCreateCompatibleBitmap"));
		return FALSE;
	}
	ogNtGdiCreateCompatibleBitmap = (NtGdiCreateCompatibleBitmap_t)dtNtGdiCreateCompatibleBitmap->Trampoline;

	if( !NT_SUCCESS(PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE)) )
	{
		KdPrint(("Error setting process create notify routine!"));
		return FALSE;
	}

	} __except(EXCEPTION_EXECUTE_HANDLER){ KdPrint(("FATAL ERROR BADBAD FUCK")); return FALSE; }
	KeUnstackDetachProcess( &ApcState );

	return TRUE;

}

VOID ASDestroyHooks( void )
{
	// @unimplented
}
