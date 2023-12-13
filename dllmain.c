#include <Windows.h>

#include <stdint.h>
#include <stdio.h>

#include "minhook/include/MinHook.h"

#ifdef DEBUG
FILE* cfile;
#define LG(s, ...) fprintf(cfile, s "\n", __VA_ARGS__)
#else
#define LG(s, ...)
#endif

/* Zend Header { */

typedef unsigned long zend_ulong;

typedef struct _zend_refcounted_h {
	uint32_t refcount; /* reference counter 32-bit */
	union {
		uint32_t type_info;
	} u;
} zend_refcounted_h;

struct _zend_refcounted {
	zend_refcounted_h gc;
};

typedef struct {
	zend_refcounted_h gc;
	zend_ulong h; /* hash value */
	size_t len;
	char val[1];
} _zend_string;

typedef _zend_string zend_string;

#define ZEND_ENDIAN_LOHI_3(lo, mi, hi) lo; mi; hi;

typedef union _zend_value {
	long lval; /* long value */
	double dval; /* double value */
	void* counted; //zend_refcounted
	zend_string* str;
	void* arr; //zend_array
	void* obj; //zend_object
	void* res; //zend_resource
	void* ref; //zend_reference
	void* ast; //zend_ast_ref
	void* zv; //zval
	void* ptr;
	void* ce; //zend_class_entry
	void* func; //zend_function
	struct {
		uint32_t w1;
		uint32_t w2;
	} ww;
} zend_value;

typedef struct _zval_struct {
	zend_value value; /* value */
	union {
		uint32_t type_info;
		struct {
			ZEND_ENDIAN_LOHI_3(
				uint8_t type, /* active type */
				uint8_t type_flags,
				union {
				uint16_t extra; /* not further specified */
			} u)
		} v;
	} u1;
	union {
		uint32_t next; /* hash collision chain */
		uint32_t cache_slot; /* cache slot (for RECV_INIT) */
		uint32_t opline_num; /* opline number (for FAST_CALL) */
		uint32_t lineno; /* line number (for ast nodes) */
		uint32_t num_args; /* arguments number for EX(This) */
		uint32_t fe_pos; /* foreach position */
		uint32_t fe_iter_idx; /* foreach iterator index */
		uint32_t property_guard; /* single property guard */
		uint32_t constant_flags; /* constant flags */
		uint32_t extra; /* not further specified */
	} u2;
} zval;

typedef enum {
	SUCCESS = 0,
	FAILURE = -1, /* this MUST stay a negative number, or it may affect functions! */
} ZEND_RESULT_CODE;

typedef ZEND_RESULT_CODE zend_result;

/* } Zend Header */

/* MinHook { */
static int CreateHook(void* target, void* detour, void** original)
{
	MH_STATUS xstat;
	if ((xstat = MH_CreateHook(target, detour, original)) != MH_OK)
	{
		LG("CreateHook(0x%p, 0x%p) was failed with reason %s", target, detour, MH_StatusToString(xstat));
		return -1;
	}

	if ((xstat = MH_EnableHook(target)) != MH_OK)
	{
		LG("EnableHook(0x%p, 0x%p) was failed with reason %s", target, detour, MH_StatusToString(xstat));
		return -2;
	}
	return 0;
}

static int RemoveHook(void* target)
{
	MH_STATUS xstat;
	if ((xstat = MH_DisableHook(target)) != MH_OK)
	{
		LG("DisableHook(0x%p) was failed with reason %s", target, MH_StatusToString(xstat));
		return -1;
	}
	if ((xstat = MH_RemoveHook(target)) != MH_OK)
	{
		LG("RemoveHook(0x%p) was failed with reason %s", target, MH_StatusToString(xstat));
		return -2;
	}
	return 0;
}

/* } MinHook */

/* Utils { */

static char* RandString(char* str, size_t size)
{
	const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK";
	if (size) {
		--size;
		for (size_t n = 0; n < size; n++) {
			int key = rand() % (int)(sizeof charset - 1);
			str[n] = charset[key];
		}
		str[size] = '\0';
	}
	return str;
}

/* } Utils */

typedef int (__cdecl* pCompileString)(zval* a1, char* Src, DWORD* a3);

FARPROC dwCompileString = NULL;
pCompileString fpCompileString = NULL;

int __cdecl DetourCompileString(zval* a1, char* Src, DWORD* a3) 
{
	zend_string* str = a1->value.str;
	size_t len = strlen(str->val) + 16;

	if (strstr(Src, "eval()'d code")) {

		srand((unsigned int)a1 + len);

		char rand_string[6] = { 0 };
		RandString(rand_string, sizeof rand_string);

		char prefix[] = { 'f', 'i', 'l', 'e', 's', '_', 0 };
		char ext[] = { '.', 'p', 'h', 'p', 0 };

		char name[(sizeof prefix - 1) + sizeof rand_string + (sizeof ext - 1) + 1] = { 0 };

		strcat(name, prefix);
		memcpy(name + sizeof prefix - 1, rand_string, sizeof rand_string);
		strcat(name, ext);

		FILE* fp = fopen(name, "a+");

		char path[512] = { 0 };
		GetFullPathNameA(name, sizeof path, path, NULL);

		if (fp) {
			size_t size = 0;

			if ((size = fwrite(((char*)str->val) - 16, sizeof(char), len, fp)) != len) {
				LG("Write file failure, %d != %d", size, len);
			}
			else {
				LG("Sucessful write eval'd code '%s' %d bytes", path, size);
			}

			fclose(fp);
		}
		else {
			LG("Unable to create file");
		}
	}

	return fpCompileString(a1, Src, a3);
}

void main()
{
	if (MH_Initialize() != MH_OK) {
		LG("MH Initialize error");

		ExitProcess(EXIT_FAILURE);
	} 
	else {
		LG("CompileString create hook");

		if (CreateHook(dwCompileString, &DetourCompileString, (void**)&fpCompileString) != 0)
			ExitProcess(EXIT_FAILURE);
		
		while (TRUE) {
			if (GetAsyncKeyState(VK_END) & 1) {
				break;
			}
		}

		LG("CompileString remove hook & uninitialize minhook");

		if (RemoveHook(dwCompileString) != 0 || MH_Uninitialize() != MH_OK)
			ExitProcess(EXIT_FAILURE);
		
		ExitProcess(EXIT_SUCCESS);
	}
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID unk)
{
	BOOL start = FALSE;

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		
#ifdef DEBUG
		AllocConsole();
		freopen_s(&cfile, "CONOUT$", "w", stdout);
		if (!cfile && MessageBoxA(0, "Unable to open handle for console. Continue?", "SoulEngine Decompiler", MB_OKCANCEL | MB_ICONWARNING) == IDCANCEL) {
			ExitProcess(EXIT_FAILURE);
		}
#endif

		HMODULE php5ts = GetModuleHandleA("php5ts.dll");

		if (!php5ts)
			php5ts = LoadLibraryA("php5ts.dll");

		if (php5ts) {
			dwCompileString = GetProcAddress(php5ts, "compile_string");

			if (dwCompileString) {
				CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)main, NULL, 0, NULL);
				start = TRUE;
			}
			else LG("Proc 'compile_string' not found");
		}
		else LG("Handle of php5ts.dll not found");
		
		CloseHandle(hModule);
	}

	if (!start)
		ExitProcess(EXIT_FAILURE);
	
	return TRUE;
}