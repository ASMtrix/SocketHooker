#ifndef ____ARRAY___
#define ____ARRAY___

#ifndef ____memory___
#include "memory.h"
#endif


#ifndef ____ARRAY___
#include "array.h"
#endif

struct arrayinfo 
{
	int *pointer;
	struct arrayinfo* next;
	struct arrayinfo* prev;
};

struct array
{
	int count;
	struct arrayinfo* head;
	struct arrayinfo* tail;
};

void AddToArray(struct array* Array, int *pointer);
int *GetFromArray(struct array* Array, int index);
void FreeArray(struct array* Array);

void AddToArray(struct array* Array, int *pointer)
{
	if (Array->head == NULL)
	{
		Array->head = (struct arrayinfo*) Memory(sizeof(struct arrayinfo));
		Array->head->pointer = pointer;
		Array->head->next=NULL;
		Array->head->prev=NULL;
		Array->tail = Array->head;
	} else {
		Array->tail->next = (struct arrayinfo*) Memory(sizeof(struct arrayinfo));
		Array->tail->next->pointer = pointer;
		Array->tail->next->next = NULL;
		Array->tail->next->prev = Array->tail;
		Array->tail = Array->tail->next;
	}
	Array->count++;
}

int *GetFromArray(struct array* Array, int index)
{
	struct arrayinfo* temp = Array->head;
	int count=0;
	
	while (temp != NULL)
	{
		if (count == index)
		{
			return temp->pointer;
		}

		count++;

		temp = temp->next;
	}

	return NULL;
}


void FreeArray(struct array* Array)
{
	struct arrayinfo* temp=NULL;

	while (temp != NULL)
	{
		struct arrayinfo* unlink = Array->head;
		Array->head = Array->head->next;
		FreeMemory((int*) unlink->pointer);
		FreeMemory((int*)unlink);

	}
}	
#endif
