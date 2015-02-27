#include "Main.h"
#include "Toolset.h"
#include "Detour.h"
#include "ADE32.h"

static int Count;

struct DetourObject_s* DtCreateDetour( ULONG OldAddress, ULONG NewAddress )
{
	ULONG TrampolineTag = '1RT' + Count * 0x010000;
	ULONG ObjectTag = '1TD' + Count * 0x010000;
	PUCHAR CurrOpcode;
	int i;

	struct DetourObject_s* Result;
	if( !OldAddress || !NewAddress )
		return NULL;

	Result = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct DetourObject_s), ObjectTag);
	if(!Result)
		return NULL;

	CurrOpcode = (PUCHAR)OldAddress;
	while(Result->OpcodeLen < 5)
	{
		i = oplen(CurrOpcode);
		if(i == 0)
		{
			ExFreePoolWithTag(Result, ObjectTag);
			return NULL;
		}

		Result->OpcodeLen += i;
		CurrOpcode += i;
	}

	Result->Set = FALSE;
	Result->TrampolineTag = TrampolineTag;
	Result->ObjectTag = ObjectTag;
	Result->OldAddress = OldAddress;
	Result->NewAddress = NewAddress;
	Result->Trampoline = (ULONG)ExAllocatePoolWithTag(NonPagedPool, Result->OpcodeLen+6, TrampolineTag);
	if(!Result->Trampoline)
	{
		ExFreePoolWithTag(Result, ObjectTag);
		return NULL;
	}

	RtlCopyMemory((void*)Result->Trampoline, (void*)OldAddress, Result->OpcodeLen);
	*(UCHAR*)(Result->Trampoline + Result->OpcodeLen + 0) = 0xE9;
	*(ULONG*)(Result->Trampoline + Result->OpcodeLen + 1) = (OldAddress +  Result->OpcodeLen) - (Result->Trampoline + Result->OpcodeLen + 5);

	_asm
	{
		push eax
			mov eax, CR0
			and eax, 0FFFEFFFFh
			mov CR0, eax
			pop eax
			cli
	}

	__try
	{
		*(UCHAR*)(OldAddress + 0) = 0xE9;
		*(ULONG*)(OldAddress + 1) = NewAddress - OldAddress - 5;
		for(i=5; i < Result->OpcodeLen; i++)
			*(UCHAR*) (OldAddress + i) = 0x90;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		KdPrint(("Exception in "__FUNCTION__" Code: 0x%08x", GetExceptionCode()));
		ExFreePoolWithTag((PVOID)Result->Trampoline, TrampolineTag);
		ExFreePoolWithTag(Result, ObjectTag);
		return NULL;
	}

	_asm
	{
		sti
			push eax
			mov eax, CR0
			or eax, NOT 0FFFEFFFFh
			mov CR0, eax
			pop eax
	}

	Result->Set = TRUE;
	return Result;
}

BOOLEAN DtCheckDetour( struct DetourObject_s* Obj )
{
	ULONG CheckAddress = Obj->NewAddress-Obj->OldAddress-5;
	ULONG CheckOrigin = Obj->OldAddress;
	BYTE bAddress[4] = { 0, 0, 0, 0 };

	if( !Obj->Set )
		return TRUE; // Can't be modified because not set :p

	*(DWORD*)(&bAddress[0]) = CheckAddress;

	KdPrint(("Check: 0x%02X 0x%02X 0x%02X 0x%02X", bAddress[0], bAddress[1], bAddress[2],
		bAddress[3]));
	KdPrint(("Origin: 0x%02X 0x%02X 0x%02X 0x%02X", (*(BYTE*)(CheckOrigin+1)), (*(BYTE*)(CheckOrigin+2)),
		(*(BYTE*)(CheckOrigin+3)), (*(BYTE*)(CheckOrigin+4)) ));

	__try
	{
		if( (*(BYTE*)(CheckOrigin)) == 0xE9 )
		{
			if( (*(BYTE*)(CheckOrigin+1)) == bAddress[0] &&
				(*(BYTE*)(CheckOrigin+2)) == bAddress[1] &&
				(*(BYTE*)(CheckOrigin+3)) == bAddress[2] &&
				(*(BYTE*)(CheckOrigin+4)) == bAddress[3]
			)
			{
				// Detour not modified
				return TRUE;
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		KdPrint(("Exception in "__FUNCTION__" Code: 0x%08x", GetExceptionCode()));
		return TRUE; // Couldn't check so assume it's not modified
	}

	// Detour modified
	return FALSE;
}

BOOLEAN DtKillDetour( struct DetourObject_s* Obj )
{
	ULONG ObjectTag;
	ULONG TrampolineTag;
	if(!Obj || !Obj->Set)
		return FALSE;

	ObjectTag = Obj->ObjectTag;
	TrampolineTag = Obj->TrampolineTag;
	Obj->Set = FALSE;

	RtlCopyMemory((void*)Obj->OldAddress, (void*)Obj->Trampoline, Obj->OpcodeLen);

	ExFreePoolWithTag((void*)Obj->Trampoline, TrampolineTag);
	ExFreePoolWithTag(Obj, ObjectTag);
	return TRUE;
}
