#ifndef ____memory___
#define ____memory___

void* Memory(int size);
void FreeMemory(int* pointer);

void* Memory(int size)
{
	#ifdef WINDOWS
		return VirtualAlloc(0,size,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
	#else
		return malloc(size);
	#endif
}


void FreeMemory(int* pointer)
{
	#ifdef WINDOWS
		VirtualFree(pointer,0,MEM_RELEASE);
	#else
		//maybe this doesn't work?
		free(pointer);
		pointer=0;
	#endif
}

#endif
