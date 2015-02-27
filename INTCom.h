#ifndef __INTCOM__H
#define __INTCOM__H

BOOLEAN RemoveServiceFromTables( VOID );
BOOLEAN AddServiceToTables( VOID );
extern unsigned int iServiceID;
extern PServiceDescriptorTableEntry_t KeServiceDescriptorTableShadow;

#include "AntiScreenshot.h" // HDC

// Service ID's
#define X_CHECK_PRESENCE     0x000000A1l
#define X_SET_THREAD_CONTEXT 0x000000B1l
#define X_DRAWING_IS_SAFE    0x000000C1l
#define X_SET_DEVICE_HANDLES 0x000000E1l

typedef struct set_thread_context_s
{
	HANDLE hThread;
	CONTEXT* pContext;
	unsigned int bSpoofLock;
	unsigned int bSuccess;
}set_thread_context_t;

typedef struct ioctl_request_s
{
	unsigned int iServiceNumber;
}ioctl_request_t;

typedef struct device_handles_s
{
	HDC hWindowDC; // GetWindowDC
	HDC hClientAreaDC; // GetDC
}device_handles_t;

#endif 