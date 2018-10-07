
// by simon yeung, 30/09/2018
// all rights reserved

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <winnt.h>
#include <memory>

// from https://msdn.microsoft.com/en-us/library/yf86a8ts.aspx
#pragma warning( disable : 4278 )
#pragma warning( disable : 4146 )
#import "libid:80cc9f66-e7d8-4ddd-85b6-d9e6cd0e93e2" version("8.0") lcid("0") raw_interfaces_only named_guids	//The following #import imports EnvDTE based on its LIBID.
#pragma warning( default : 4146 )
#pragma warning( default : 4278 )

// from https://handmade.network/forums/wip/t/1479-sample_code_to_programmatically_attach_visual_studio_to_a_process
EnvDTE::Process* FindVSProcess(DWORD TargetPID)
{
	HRESULT hr;

	static const wchar_t* ProgID = L"VisualStudio.DTE";

	CLSID Clsid;
	CLSIDFromProgID(ProgID, &Clsid);

	IUnknown* Unknown;
	hr = GetActiveObject(Clsid, 0, &Unknown);
	if (FAILED(hr))
		return nullptr;

	EnvDTE::_DTE* Interface;

	hr = Unknown->QueryInterface(&Interface);
	if (FAILED(hr))
		return nullptr;

	EnvDTE::Debugger* Debugger;
	hr = Interface->get_Debugger(&Debugger);
	if (FAILED(hr))
		return nullptr;

	EnvDTE::Processes* Processes;
	hr = Debugger->get_LocalProcesses(&Processes);
	if (FAILED(hr))
		return nullptr;

	long Count = 0;
	hr = Processes->get_Count(&Count);
	if (FAILED(hr))
		return nullptr;

	EnvDTE::Process* Result = nullptr;
	for (int i = 1; i < Count; ++i)	// index 0 is invalid, hr == DISP_E_BADINDEX
	{
		EnvDTE::Process* Process;

		// get the process, but sometimes may fail,
		// so we re-try a number of times to get it...
		const int	retryTime		= 5000;	// ms
		const int	retryInterval	= 10;	// ms
		const int	retryCntMax		= retryTime / retryInterval;
		int			retryCnt		= 0;
		do
		{
			hr = Processes->Item(variant_t(i), &Process);
			if (FAILED(hr))	// usually return RPC_E_CALL_REJECTED if failed
			{				// so wait a bit to let it get ready
				Sleep(retryInterval);
				++retryCnt;
			}
			else
				retryCnt= retryCntMax;
		} while (retryCnt < retryCntMax);

		if (FAILED(hr))
			continue;

		long ProcessID;
		hr = Process->get_ProcessID(&ProcessID);
		
		if (SUCCEEDED(hr) && ProcessID == TargetPID)
		{
			Result = Process;
			break;
		}
	}

	return Result;
}

void AttachVS()
{
	DWORD			TargetPID= GetCurrentProcessId();
	EnvDTE::Process *Process = FindVSProcess(TargetPID);
	if (Process)
		Process->Attach();
}

void DetachVS(bool waitForBreakOrEnd)
{
	DWORD			TargetPID= GetCurrentProcessId();
	EnvDTE::Process *Process = FindVSProcess(TargetPID);
	if (Process)
		Process->Detach(variant_t(waitForBreakOrEnd));
}

bool		FileIOisExist(const char* fileName)
{
	DWORD dwAttrib = GetFileAttributes(fileName);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

bool		FileIOcopy(const char* fromFile, const char* toFile, bool overwriteExisting)
{
	return CopyFile(fromFile, toFile, !overwriteExisting);
}

FILETIME	FileIOgetLastWriteTime(const char* fileName)
{
	WIN32_FILE_ATTRIBUTE_DATA data;
	BOOL ok= GetFileAttributesEx(fileName, GetFileExInfoStandard, &data);
	return data.ftLastWriteTime;
}

bool		FileIOisWriting(const char* fileName)
{
	HANDLE h= CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
       CloseHandle(h);
       return false;
    }
    return (GetLastError() == ERROR_SHARING_VIOLATION);
}

size_t		CStrlastIndexOfChar(const char* str, char findChar)
{
	intptr_t i= strlen(str) - 1;
	while ( i >= 0 )
	{
		if (str[i]== findChar)
			return i;
		--i;
	}
	return (size_t)-1;	
}

// replace the last char of file name to '_'
// which maintain the same file name length to avoid 
// wrong offset in other area of the DLL
bool patchFileName(char* fileName)
{
	size_t	dotIdx=	CStrlastIndexOfChar(fileName, '.');
	if (dotIdx != (size_t)-1)
	{
		fileName[dotIdx-1]= '_';
		return true;
	}
	else
		return false;
}

#define FREE_FILE(msg, retVal)			{							\
											free(fileContent);		\
											return retVal;			\
										}

#pragma warning( push )
#pragma warning( disable : 4200 )		// for flexible array member
struct CV_INFO_PDB70
{
	DWORD	CvSignature;
	GUID	Signature;
	DWORD	Age;
	BYTE	PdbFileName[];
};
#pragma warning( pop )

// from https://fungos.github.io/blog/2017/11/20/cr.h-a-simple-c-hot-reload-header-only-library/
bool patchDLL(const char* dllPath, char patchedDllPath[MAX_PATH], char patchedPdbPath[MAX_PATH])
{
	// init
	patchedDllPath[0]= '\0';
	patchedPdbPath[0]= '\0';

	// check DLL exist
	if (!FileIOisExist(dllPath))
		return false;

	// create new DLL file Path
	strcpy(patchedDllPath, dllPath);
	if (!patchFileName(patchedDllPath))
		return false;
	
	// open DLL and copy content to fileContent for easy parsing of the DLL content
	DWORD byteRead;
	HANDLE file= CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	size_t	fileSize	= GetFileSize((HANDLE)file, NULL);
	BYTE*	fileContent	= (BYTE*)malloc(fileSize);
	bool	isFileReadOk= ReadFile((HANDLE)file, fileContent, (DWORD)fileSize, &byteRead, NULL);
	CloseHandle(file);
	if (!isFileReadOk || byteRead!=fileSize)
		FREE_FILE("Failed to read file.\n", false);

	// check signature
	IMAGE_DOS_HEADER dosHeader= *(IMAGE_DOS_HEADER*)fileContent;
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		FREE_FILE("Not IMAGE_DOS_SIGNATURE\n", false);
	
	// IMAGE_NT_HEADERS
	IMAGE_NT_HEADERS ntHeader= *((IMAGE_NT_HEADERS*)(fileContent + dosHeader.e_lfanew));
	if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
		FREE_FILE("Not IMAGE_NT_SIGNATURE\n", false);

	IMAGE_DATA_DIRECTORY debugDir;
	if (ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC && ntHeader.FileHeader.SizeOfOptionalHeader== sizeof(IMAGE_OPTIONAL_HEADER))
		debugDir= ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	else
		FREE_FILE("Not IMAGE_NT_OPTIONAL_HDR_MAGIC\n", false);

	if (debugDir.VirtualAddress == 0 || debugDir.Size == 0)
		FREE_FILE("No IMAGE_DIRECTORY_ENTRY_DEBUG data\n", false);
	
	// find debug section
	int						debugDirSectionIdx	= -1;
	IMAGE_SECTION_HEADER*	allSectionHeaders	= (IMAGE_SECTION_HEADER*)(fileContent + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	for(int j=0; j<ntHeader.FileHeader.NumberOfSections; ++j)
	{
		IMAGE_SECTION_HEADER sectionHeader= allSectionHeaders[j];
		if ((debugDir.VirtualAddress >= sectionHeader.VirtualAddress) &&
			(debugDir.VirtualAddress < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize))
		{
			debugDirSectionIdx= j;
			break;
		}
	}

	// read debug section
	char*	pdbPath= nullptr;
	char	originalPdbPath[MAX_PATH];
	if (debugDirSectionIdx != -1)
	{
		// loop all debug directory
		int						numDebugDir		= debugDir.Size / (int)sizeof(IMAGE_DEBUG_DIRECTORY);
		IMAGE_SECTION_HEADER	sectionHeader	= allSectionHeaders[debugDirSectionIdx];
		IMAGE_DEBUG_DIRECTORY*	allImageDebugDir= (IMAGE_DEBUG_DIRECTORY*)(fileContent + debugDir.VirtualAddress - (sectionHeader.VirtualAddress - sectionHeader.PointerToRawData));
		for(int i=0; i<numDebugDir; ++i)
		{
			IMAGE_DEBUG_DIRECTORY imageDebugDir= allImageDebugDir[i];
			if (imageDebugDir.Type == IMAGE_DEBUG_TYPE_CODEVIEW)
			{
				DWORD signature= *((DWORD*)(fileContent + imageDebugDir.PointerToRawData));
				if (signature == 'SDSR')	// RSDS type, i.e. PDB70
				{
					CV_INFO_PDB70* debugInfo= ((CV_INFO_PDB70*)(fileContent + imageDebugDir.PointerToRawData));
					pdbPath= (char*)debugInfo->PdbFileName;
					strcpy(originalPdbPath, pdbPath);
					break;
				}
			}
		}
	}
	
	if (pdbPath == nullptr)
		FREE_FILE("No debug section is found.\n", false);

	// create new DLL and pdb
	patchFileName(pdbPath);
	if (FileIOisExist(originalPdbPath))
	{
		strcpy(patchedPdbPath, pdbPath);
		FileIOcopy(originalPdbPath, pdbPath, true);		// copy new PDB
	}
	HANDLE patchedDLL= CreateFile(patchedDllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD byteWrite;
	WriteFile(patchedDLL, fileContent, (DWORD)fileSize, &byteWrite, nullptr);	// generate patched DLL which points to the new PDB
	CloseHandle(patchedDLL);

	// clean up
	FREE_FILE("Patching DLL succeeded!!!.\n", true);
}

typedef bool (*dll_tick)();

struct DLLdata
{
	HMODULE		dllHandle;
	dll_tick	tick;
};

DLLdata loadDLL(const char* dllPath)
{
	DLLdata data = { nullptr };

	// load the DLL
	data.dllHandle= LoadLibrary(dllPath);
	if (dllPath == nullptr)
		return data;

	// get DLL function pointer
	data.tick= (dll_tick)GetProcAddress(data.dllHandle, "tick");
	if (data.tick == nullptr)
	{
		CloseHandle(data.dllHandle);
		data= {nullptr};
		return data;
	}

	return data;
}

void unloadDLL(DLLdata dll)
{
	if(dll.dllHandle)
		FreeLibrary(dll.dllHandle);
}

int main(int argc, char* argv[])
{
	bool isStartWithDebugger= IsDebuggerPresent();
	printf("Start with debugger: %i\n", isStartWithDebugger);
	
    CoInitialize(0);	
	if (isStartWithDebugger)
	{
		// re-attach the debugger to avoid killing the app process when stopping the debugger
		DetachVS(true);
		AttachVS();
	}

	// compose a full path to the DLL
	const char* dllName= "dll.dll";
    char exePath[MAX_PATH];
	char dllPath[MAX_PATH];
    GetModuleFileName( NULL, exePath, MAX_PATH );
	size_t exeLen= strlen(exePath);
	strcpy(dllPath, exePath);
	strcpy(dllPath + exeLen - 7, dllName);	// assume exe file named with "exe.exe", which is of length 7
	const char* loadDllPath= dllPath;

	// create a copy of DLL and PDB
	char patchedDllPath[MAX_PATH]= {'\0'};
	char patchedPdbPath[MAX_PATH]= {'\0'};
	bool ok= patchDLL(dllPath, patchedDllPath, patchedPdbPath);
	if (ok)
	{
		loadDllPath= patchedDllPath;
		printf("Patch DLL succeeded\n");
	}
	else
	{
		printf("Patch DLL failed\n");
		getchar();
	    CoUninitialize();
		return 1;
	}

	// load DLL
	FILETIME	dllLastWriteTime= FileIOgetLastWriteTime(dllPath);
	DLLdata		dll				= loadDLL(loadDllPath);
	if (dll.dllHandle == nullptr)
	{
		printf("Failed to load DLL.\n");
		getchar();
	    CoUninitialize();
		return 1;
	}

	// loop to execute DLL function
	bool isTick= true;
	while (isTick)
	{
		isTick= dll.tick();
		Sleep(16);
		
		// check is DLL updated
		FILETIME dllTimeNew= FileIOgetLastWriteTime(dllPath);
		if (!(	dllLastWriteTime.dwHighDateTime	== dllTimeNew.dwHighDateTime &&
				dllLastWriteTime.dwLowDateTime	== dllTimeNew.dwLowDateTime))
		{
			// the DLL may not yet finish compliation and still writing to DLL
			if (!FileIOisWriting(dllPath))
			{
				if (IsDebuggerPresent())
					DetachVS(true);	// detach to release PDB lock

				// reload DLL
				unloadDLL(dll);
				ok= patchDLL(dllPath, patchedDllPath, patchedPdbPath);
				if (ok && (dll= loadDLL(patchedDllPath)).dllHandle)
				{
					if (isStartWithDebugger)
						AttachVS();	// re-attach debugger

					dllLastWriteTime= dllTimeNew;
					printf("DLL reloaded.\n");
				}
				else
				{
					printf("Failed to reload DLL.\n");
					break;
				}
			}
		}
	}
	
	// clean up
	printf("shut down.\n");
	getchar();
	unloadDLL(dll);
	if (patchedDllPath[0] != '\0')
		DeleteFile(patchedDllPath);
	if (patchedPdbPath[0] != '\0')
	{
		if (IsDebuggerPresent())
			DetachVS(true);	// may fail to delete the patchedPdbPath if a debugger 
							// is attached, MSVC locks the PDB file, 
							// so detach the debugger first.
		DeleteFile(patchedPdbPath);
	}
	
    CoUninitialize();
	return 0;
}
