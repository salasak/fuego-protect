#ifndef __ANTISCREENSHOT__H
#define __ANTISCREENSHOT__H

DECLARE_HANDLE(HBM);
DECLARE_HANDLE(HDEV);
DECLARE_HANDLE(HSURF);
DECLARE_HANDLE(DHSURF);
DECLARE_HANDLE(DHPDEV);
DECLARE_HANDLE(HDRVOBJ);

typedef ULONG ROP4;
typedef ULONG HDC;
typedef ULONG HBITMAP;
typedef INT HWND;
typedef unsigned int UINT;

extern BOOLEAN g_bDrawingIsSafe;
extern BOOLEAN g_bScreenIsSafe;
extern BOOLEAN g_bGameIsActive;
extern HDC hDeviceHandle;
extern HDC hClientArea;

BOOLEAN ASInitializeHooks( void );
VOID ASDestroyHooks( void );

typedef struct _BRUSHOBJ {
	ULONG  iSolidColor;
	PVOID  pvRbrush;
	FLONG  flColorType;
} BRUSHOBJ;

typedef struct  tagCOLORADJUSTMENT {
	WORD    caSize;
	WORD    caFlags;
	WORD    caIlluminantIndex;
	WORD    caRedGamma;
	WORD    caGreenGamma;
	WORD    caBlueGamma;
	WORD    caReferenceBlack;
	WORD    caReferenceWhite;
	SHORT   caContrast;
	SHORT   caBrightness;
	SHORT   caColorfulness;
	SHORT   caRedGreenTint;
} COLORADJUSTMENT, *PCOLORADJUSTMENT, *LPCOLORADJUSTMENT;


typedef struct tagPOINT {
	LONG x;
	LONG y;
} POINT,POINTL,*PPOINT,*LPPOINT,*PPOINTL,*LPPOINTL;

typedef struct tagSIZE {
	LONG cx;
	LONG cy;
} SIZE,SIZEL,*PSIZE,*LPSIZE,*PSIZEL,*LPSIZEL;

typedef struct tagRECTL {
	LONG left;
	LONG top;
	LONG right;
	LONG bottom;
} RECTL,*PRECTL,*LPRECTL;

typedef struct _SURFOBJ {
	DHSURF  dhsurf;
	HSURF  hsurf;
	DHPDEV  dhpdev;
	HDEV  hdev;
	SIZEL  sizlBitmap;
	ULONG  cjBits;
	PVOID  pvBits;
	PVOID  pvScan0;
	LONG  lDelta;
	ULONG  iUniq;
	ULONG  iBitmapFormat;
	USHORT  iType;
	USHORT  fjBitmap;
} SURFOBJ;

typedef struct _XLATEOBJ {
	ULONG  iUniq;
	FLONG  flXlate;
	USHORT  iSrcType;
	USHORT  iDstType;
	ULONG  cEntries;
	ULONG  *pulXlate;
} XLATEOBJ;

typedef struct _CLIPOBJ {
	ULONG  iUniq;
	RECTL  rclBounds;
	BYTE  iDComplexity;
	BYTE  iFComplexity;
	BYTE  iMode;
	BYTE  fjOptions;
} CLIPOBJ;

typedef BOOL (NTAPI *EngStretchBlt_t)    ( 
										   SURFOBJ *  psoDest,
										   SURFOBJ *  	psoSrc,
										   SURFOBJ * 	psoMask,
										   CLIPOBJ *  	pco,
										   XLATEOBJ *  	pxlo,
										   COLORADJUSTMENT *  	pca,
										   POINTL *  	pptlHTOrg,
										   RECTL *  	prclDest,
										   RECTL *  	prclSrc,
										   POINTL *  	pptlMask,
										   ULONG  	iMode	 
										   ); 	
typedef BOOL (NTAPI *EngBitBlt_t)		 (
										  IN SURFOBJ  *psoTrg,
										  IN SURFOBJ  *psoSrc,
										  IN SURFOBJ  *psoMask,
										  IN CLIPOBJ  *pco,
										  IN XLATEOBJ  *pxlo,
										  IN RECTL  *prclTrg,
										  IN POINTL  *pptlSrc,
										  IN POINTL  *pptlMask,
										  IN BRUSHOBJ  *pbo,
										  IN POINTL  *pptlBrush,
										  IN ROP4  rop4
										  );

typedef BOOL(NTAPI *NtGdiBitBlt_t)( HDC hdcDst, INT x, INT y, INT cx, INT cy, HDC hdcSrc, INT xSrc, INT ySrc, DWORD rop4,
								   DWORD crBackColor, FLONG fl ); 
typedef BOOL (NTAPI *NtGdiStretchBlt_t) ( IN HDC  hdcDst,  
						   IN INT  xDst,  
						   IN INT  yDst,  
						   IN INT  cxDst,  
						   IN INT  cyDst,  
						   IN HDC  hdcSrc,  
						   IN INT  xSrc,  
						   IN INT  ySrc,  
						   IN INT  cxSrc,  
						   IN INT  cySrc,  
						   IN DWORD  dwRop,  
						   IN DWORD  dwBackColor   
						   );
typedef DWORD (NTAPI *NtGdiGetPixel_t)( IN HDC hdc, IN INT x, IN INT y );

typedef HBITMAP (NTAPI *NtGdiCreateCompatibleBitmap_t)(IN HDC hdc, IN INT cx, IN INT cy);


#endif 