#include <Windows.h>

#include <stdint.h>
#include <stdio.h>

#include "minhook/include/MinHook.h"

#include "xxhash/xxhash.h"

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

/* XXHash { */

typedef struct link_hash_t {
	XXH64_hash_t hash;
	struct link_hash_t* before, * next;
} link_hash_t, * plink_hash_t;

plink_hash_t phFile = NULL;

/* } XXHash */

const char szPhpModuleName[] = "php5ts.dll";

typedef int (__cdecl* pCompileString)(zval* a1, char* Src, DWORD* a3);

FARPROC dwCompileString = NULL;
pCompileString fpCompileString = NULL;

int __cdecl DetourCompileString(zval* a1, char* Src, DWORD* a3) 
{
	zend_string* pZStrPhpCode = a1->value.str;

	if (strstr(Src, "eval()'d code")) {
		size_t iPhpCodeLength = strlen(pZStrPhpCode->val) + 0x10;
		const char* szPhpCode = ((char*)pZStrPhpCode->val) - 0x10;
		XXH64_hash_t XxhPhpCodeHash = XXH3_64bits(szPhpCode, iPhpCodeLength);

		char* szOutputFilePath = malloc(MAX_PATH * sizeof(char));
		{
			GetModuleFileNameA(NULL, szOutputFilePath, MAX_PATH); // get current file path
			char* pFilename = strrchr(szOutputFilePath, '\\') + 1; // pointer to filename
			char* pFileext = strrchr(pFilename, '.') + 1; // pointer to file extension
			memset(pFileext, 0, strlen(pFileext)); // remove extension
			*(pFileext - 1) = '_'; // replace '.' to '_'

			char szBufferHash[sizeof(XXH64_hash_t) + 1] = { 0 };
			_itoa_s(XxhPhpCodeHash, szBufferHash, sizeof szBufferHash, 16);

			strcat(szOutputFilePath, szBufferHash);
			strcat(szOutputFilePath, ".php");
		}

		FILE* hFile = fopen(szOutputFilePath, "a+");

		if (hFile) {
			BOOL bCodeAlreadyStealed = FALSE;

			/* Find code hash in list */
			plink_hash_t phCurrent = phFile;
			while (phCurrent != NULL) {
				if (phCurrent->hash == XxhPhpCodeHash) {
					bCodeAlreadyStealed = TRUE;
					break;
				}
				phCurrent = phCurrent->before;
			}
			/* ---- */

			if (!bCodeAlreadyStealed) {

				/* Create new hash of php code */
				plink_hash_t phBefore = phFile;
				phFile = malloc(sizeof(link_hash_t));
				phFile->hash = XxhPhpCodeHash;
				phFile->before = phBefore;
				phFile->next = NULL;
				if (phBefore != NULL)
					phBefore->next = phFile;
				/* ---- */

				size_t iFileWritten = 0;
				if ((iFileWritten = fwrite(szPhpCode, sizeof(char), iPhpCodeLength, hFile)) != iPhpCodeLength) {
					LG("[0x%x] Write file failure, %d != %d", iFileWritten, iPhpCodeLength);
				}
				else {
					LG("[0x%x] Sucessful write eval'd code '%s' %d bytes", szOutputFilePath, iFileWritten);
				}
			}
			else {
				LG("[0x%x] Already stealed", XxhPhpCodeHash);
			}

			fclose(hFile);
		}
		else {
			LG("[0x%x] Unable to create file", XxhPhpCodeHash);
		}

		free(szOutputFilePath);
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

		plink_hash_t phCurrent = phFile;
		while (phCurrent != NULL) {
			plink_hash_t phBefore = phCurrent->before;
			free(phCurrent);
			phCurrent = phBefore;
		}
		
		ExitProcess(EXIT_SUCCESS);
	}
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID unk)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		BOOL bThreadStarted = FALSE;

		DisableThreadLibraryCalls(hModule);
		
#ifdef DEBUG
		AllocConsole();
		freopen_s(&cfile, "CONOUT$", "w", stdout);
		if (!cfile && MessageBoxA(0, "Unable to open handle for console. Continue?", "SoulEngine Decompiler", MB_OKCANCEL | MB_ICONWARNING) == IDCANCEL) {
			ExitProcess(EXIT_FAILURE);
		}
#endif
		HMODULE hPhpModule = GetModuleHandleA(szPhpModuleName);

		if (!hPhpModule)
			hPhpModule = LoadLibraryA(szPhpModuleName);

		if (hPhpModule) {
			dwCompileString = GetProcAddress(hPhpModule, "compile_string");

			if (dwCompileString && CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)main, NULL, 0, NULL) != NULL)
				bThreadStarted = TRUE;
			else LG("Proc 'compile_string' not found");
		}
		else LG("Handle of %s not found", szPhpModuleName);

		if (!bThreadStarted)
			ExitProcess(EXIT_FAILURE);
		
		CloseHandle(hModule);
	}

	return TRUE;
}