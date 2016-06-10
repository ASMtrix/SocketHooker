// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS

#include "stdafx.h"
#include <cstdio>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commCtrl.h>
#include <stdint.h>
#include <stdio.h>
#include "array.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

struct npacket
{
	int size;
	char* packet;
	char* function;
};

char* nextAddr=NULL;
char* chatNextAddr=NULL;
char* nextRecvAddr=NULL;
bool isRunning=true;
BOOL EnableDebugPrivilege();
HWND hwndListView=0;
int numOfPackets=0;
struct array *packetInfo=NULL;


void *HookFunc(BYTE *src, const BYTE *dst, const int len);
LRESULT CALLBACK MainFormCallback(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam); 
void *SmartHookFunc(BYTE *src, const BYTE *dst, const int len);
void __cdecl LoadWindow();
void *SmartHookFunc(BYTE *src, const BYTE *dst, const int len);
void* SearchMemory(char* pattern, char* fromAddress, char* toAddress, int size);
void addToItem(char* buf, char *functioName);
void AddRecvPackets(	SOCKET s,
	char* buf,
	int len,
	int flags);
void AddSendPackets(	SOCKET s,
	char* buf,
	int len,
	int flags);


void __cdecl DoStack();

int WINAPI HookedSend(
	SOCKET s,
	char *buf,
	int len,
	int flags
);


int WINAPI HookedRecv(
	SOCKET s,
	char *buf,
	int len,
	int flags
);



enum {
COL1,COL2,COL3,COL4
};


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	DisableThreadLibraryCalls(hModule);

	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		{
			//EnableDebugPrivilege();
			CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(LoadWindow),NULL,NULL,NULL);

			break;
		}	
	}

	return TRUE;
}

LRESULT CALLBACK MainFormCallback(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	LRESULT result=0;

	switch(msg)
	{
		case WM_NOTIFY:
		{
			LPNMHDR nmh;
			nmh = (LPNMHDR) lParam;
			switch (nmh->code)
			{
				case LVN_COLUMNCLICK:
				{
					MessageBoxA(NULL,"testing","testing",MB_OK);
					break;
				}
			}
			break;
		}
		case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
				case 100:
				{
					HMODULE libModule = NULL;
					char* realAddr=NULL;
					char* realAddr2=NULL;

					libModule = GetModuleHandleA("Ws2_32.dll");
					realAddr = (char*) GetProcAddress(libModule,"send");

					nextAddr = (char*) SmartHookFunc((PBYTE) realAddr, (PBYTE) HookedSend, 5);

					realAddr2 = (char*) GetProcAddress(libModule,"recv");

					nextRecvAddr = (char*) SmartHookFunc((PBYTE) realAddr2, (PBYTE) HookedRecv, 5);
					
					CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(DoStack),NULL,NULL,NULL);

					packetInfo = (array*) Memory(sizeof(array));
					ZeroMemory(packetInfo,sizeof(array));
					packetInfo->head = NULL;
					packetInfo->tail=NULL;


					MessageBoxA(NULL,"winsock hooked","winsock hooked",MB_OK);
					break;
				}
			}
			break;
		}
		case WM_CREATE:
		{

			hwndListView = CreateWindowEx(0, WC_LISTVIEW,L"ListView",WS_BORDER | WS_VISIBLE| WS_CHILD | LVS_REPORT | LVS_EDITLABELS,10,80,585,470,hwnd,(HMENU)0,0,0);

			ListView_SetExtendedListViewStyle(hwndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVIS_FOCUSED);

			LVCOLUMNA lvcol;
			lvcol.mask=LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_FMT;
			lvcol.fmt=LVCFMT_LEFT;
			lvcol.cx=150;
			lvcol.pszText = "NO.";
			SendMessage(hwndListView, LVM_INSERTCOLUMNA,COL1,(WPARAM) &lvcol);

			lvcol.cx = 150;
			lvcol.pszText = "Byte Size";
			SendMessage(hwndListView, LVM_INSERTCOLUMNA,COL2,(WPARAM) &lvcol);

			lvcol.cx = 150;
			lvcol.pszText = "Bytes";
			SendMessage(hwndListView, LVM_INSERTCOLUMNA,COL3,(WPARAM) &lvcol);

			lvcol.cx = 150;
			lvcol.pszText = "Function";
			SendMessage(hwndListView, LVM_INSERTCOLUMNA,COL4,(WPARAM) &lvcol);


			HWND button = CreateWindowExA(0,"BUTTON", "Overwrite",WS_CHILD | WS_VISIBLE |BS_PUSHBUTTON,10,10,80,20,hwnd,(HMENU) 100, (HINSTANCE) GetWindowLong(hwnd,GWL_HINSTANCE),NULL);
			break;
		}
		case WM_DESTROY:
		{
			DestroyWindow(hwnd);
			break;
		}
		case WM_QUIT:
		{
			DestroyWindow(hwnd);
			break;
		}
		case WM_CLOSE:
		{
			break;
		}
		case WM_PAINT:
		{
			PAINTSTRUCT paint={};

			HDC hdc = BeginPaint(hwnd,&paint);
			FillRect(hdc, &paint.rcPaint, (HBRUSH) (COLOR_WINDOW));

			EndPaint(hwnd,&paint);

			break;
		}
		default:
		{
			result = DefWindowProc(hwnd,msg,wParam,lParam);
			break;
		}
	}
		
	return result;
}

void __cdecl LoadWindow()
{
	WNDCLASSA wClass = {};
	wClass.style = CS_VREDRAW | CS_HREDRAW;
	wClass.hInstance = GetModuleHandle(0);
	wClass.lpszClassName="packetcapture";
	wClass.lpfnWndProc = MainFormCallback;

	if (RegisterClassA(&wClass))
	{
		HWND hwnd = CreateWindowExA(
				0,                              
				wClass.lpszClassName,                    
				"Packet capture",    
				WS_OVERLAPPEDWINDOW,     
				CW_USEDEFAULT, CW_USEDEFAULT, 610 , 480, 
				NULL,
				NULL,
				wClass.hInstance,
				NULL
				);

		if (hwnd)
		{
			MSG msg = {};

			ShowWindow(hwnd,SW_SHOW);

			while (isRunning)
			{
				while (PeekMessage(&msg,0,0,0,PM_REMOVE))
				{
					if (msg.message == WM_DESTROY)
					{
						isRunning =false;
					} else {
						TranslateMessage(&msg);
						DispatchMessage(&msg);
					}
				}
			}
		} else {

			MessageBoxA(NULL,"Error can not created window", "Error Can not created window",MB_OK);
		}
	}
}


BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if(!OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ))
    {
        return FALSE;
    }

    if(!LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid ))
    {
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if(!AdjustTokenPrivileges( hToken, false, &tkp, sizeof( tkp ), NULL, NULL ))
    {
        return FALSE;
    }

    if(!CloseHandle( hToken ))
    {
        return FALSE;
    }

    return TRUE;
}


void *SmartHookFunc(BYTE *src, const BYTE *dst, const int len)
{
	LPVOID newAddr=0;
	LPVOID oldAddr=0;
	DWORD dwback=0;
	VirtualProtectEx(GetCurrentProcess(),src, len, PAGE_EXECUTE_READWRITE, &dwback);

	if (src[0] == 0xE9)
	{
		newAddr =  VirtualAlloc(NULL,len+5,MEM_COMMIT,PAGE_READWRITE);
		memcpy( (void*) newAddr,src,len);
		
	}

	
	oldAddr = HookFunc(src,dst,len);

	if (newAddr == 0)
	{
		return src+5;
	} 
	return newAddr;
}

int WINAPI HookedSend(
	SOCKET s,
	 char *buf,
	int len,
	int flags
)
{
	AddSendPackets(s,buf,len,flags);

	__asm
	{
		//jump to the actual function
		jmp nextAddr;
	}

	return 1;
}


int WINAPI HookedRecv(
	SOCKET s,
	char* buf,
	int len,
	int flags
)
{
	AddRecvPackets(s,buf,len,flags);

	__asm
	
	{
		//jump to the actual function
		jmp nextRecvAddr;
	}

	return 1;
}

void addToItem(char* buf, char *functioName)
{
	
	numOfPackets++;
	LVITEMA ritem={};

	ritem.mask=LVIF_TEXT;
	ritem.iItem=0;
	ritem.iSubItem=COL1;
	char countChar[256]={};
	sprintf(countChar,"%i",numOfPackets);
	ritem.pszText = countChar;

	SendMessage(hwndListView,LVM_INSERTITEMA,NULL,(WPARAM) &ritem);

	ritem.iSubItem =COL2;
	ritem.pszText = "Unknown";
	SendMessage(hwndListView,LVM_SETITEMA,NULL,(WPARAM) &ritem);

	ritem.iSubItem =COL3;
	ritem.pszText = buf;
	SendMessage(hwndListView,LVM_SETITEMA,NULL,(WPARAM) &ritem);

	ritem.iSubItem =COL4;
	ritem.pszText = functioName;
	SendMessage(hwndListView,LVM_SETITEMA,NULL,(WPARAM) &ritem);
}

void* SearchMemory(char* pattern, char* fromAddress, char* toAddress, int size)
{
	bool didMatchAll=false;
	int k=0;
	int l=0;

	for (char* i= fromAddress; i < toAddress;i++)
	{
		k=0;
		l=0;
		
		for (char* j=pattern;j<pattern+size;j++)
		{
			
			if ((BYTE) *(i+k) == (BYTE) *j)
			{
				l++;
			} else {
				break;
			}
		
			k++;
		}
		
		if (size==l)
		{
			return i;
		} 
	}
	
	return NULL;


}

void *HookFunc(BYTE *src, const BYTE *dst, const int len)
{
	BYTE *jmp = (BYTE*)malloc(len+5);
	DWORD dwback;
	
	VirtualProtectEx(GetCurrentProcess(),src, len, PAGE_EXECUTE_READWRITE, &dwback);
	memcpy(jmp, src, len); 
	jmp += len;
	jmp[0] = 0xE9;
	*(DWORD*)(jmp+1) = (DWORD)(src+len - jmp) - 5;
	src[0] = 0xE9;
	*(DWORD*)(src+1) = (DWORD)(dst - src) - 5;
	VirtualProtectEx(GetCurrentProcess(),src, len, dwback, &dwback);
	return (jmp-len);
}

char* HexToBytes(char* packet, int packetSize)
{
	return NULL;
}

void __cdecl DoStack()
{
	while (isRunning)
	{
		if (packetInfo->head != NULL)
		{
			npacket *packi = (npacket*) packetInfo->head->pointer;
			addToItem(packi->packet, packi->function);
			packetInfo->head = packetInfo->head->next;
		}
	}
}

void AddRecvPackets(	SOCKET s,
	char* buf,
	int len,
	int flags)
{
	struct npacket *PackI =(struct npacket*) malloc(sizeof(npacket));

	PackI->packet = (char*) malloc(len);
	ZeroMemory(PackI->packet,len);
	memcpy(PackI->packet, buf,len);
	PackI->function = (char*) malloc(256);
	strcpy(PackI->function, "Recv()");

	AddToArray(packetInfo, (int*) PackI);
}

void AddSendPackets(	SOCKET s,
	char* buf,
	int len,
	int flags)
{
	npacket *PackI = (npacket*) Memory(sizeof(npacket));
	PackI->packet = (char*) Memory(len);
	ZeroMemory(PackI->packet,len);
	memcpy(PackI->packet, buf,len);
	PackI->function = (char*) Memory(256);
	strcpy(PackI->function, "Send()");

	AddToArray(packetInfo, (int*) PackI);
}
