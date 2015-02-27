#ifndef __DETOUR__H_
#define __DETOUR__H_

typedef struct DetourObject_s
{
	int OpcodeLen;
	ULONG OldAddress;
	ULONG NewAddress;
	ULONG Trampoline;
	ULONG TrampolineTag;
	ULONG ObjectTag;
	BOOLEAN Set;
} DetourObject_t;

// Create a detour
struct DetourObject_s* DtCreateDetour( ULONG OldAddress, ULONG NewAddress );

// Check if detour hasn't been modified (returns FALSE if it has been)
BOOLEAN DtCheckDetour( struct DetourObject_s* Obj );

// Remove detour
BOOLEAN DtKillDetour( struct DetourObject_s* Obj );

#endif