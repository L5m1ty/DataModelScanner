#define _CRT_SECURE_NO_DEPRICATE
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>

#define aslr(x) (x - 0x400000 + (DWORD)GetModuleHandleA(nullptr))

namespace Memory {
	BOOL compare(const BYTE* location, const BYTE* aob, const char* mask) {
		for (; *mask; ++aob, ++mask, ++location) {
			__try {
				if (*mask == 'x' && *location != *aob)
					return 0;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return 0;
			}
		}
		return 1;
	}

	DWORD find_Pattern(DWORD size, BYTE* pattern, char* mask,
		BYTE protection = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
		SYSTEM_INFO SI = { 0 };
		GetSystemInfo(&SI);
		DWORD start = (DWORD)SI.lpMinimumApplicationAddress;
		DWORD end = (DWORD)SI.lpMaximumApplicationAddress;
		MEMORY_BASIC_INFORMATION mbi;
		while (start < end && VirtualQuery((void*)start, &mbi, sizeof(mbi))) {
			// Make sure the memory is committed, matches our protection, and isn't PAGE_GUARD.
			if ((mbi.State & MEM_COMMIT) && (mbi.Protect & protection) && !(mbi.Protect & PAGE_GUARD)) {
				// Scan all the memory in the region.
				for (DWORD i = (DWORD)mbi.BaseAddress; i < (DWORD)mbi.BaseAddress + mbi.RegionSize; ++i) {
					if (compare((BYTE*)i, pattern, mask)) {
						return i;
					}
				}
			}
			// Move onto the next region of memory.
			start += mbi.RegionSize;
		}
		return 0;
	}

	int Scan(DWORD mode, char* content, char* mask) {
		return find_Pattern(0x7FFFFFFF, (BYTE*)content, mask, mode);
	}
}

DWORD getParent(DWORD Instance)
{
	return *(DWORD*)(Instance + 0x34);
}

DWORD RBXGetParent(DWORD Instance)
{
	DWORD Parent = getParent(Instance);
	if (Parent)
		return Parent;
	else
		std::cout << "ERROR" << std::endl;
	return NULL;
}

static const char* GetClass(int self)
{
	return (const char*)(*(int(**)(void))(*(int*)self + 16))();
}

static int FindFirstClass(int Instance, const char* Name)
{
	DWORD StartOfChildren = *(DWORD*)(Instance + 44);
	DWORD EndOfChildren = *(DWORD*)(StartOfChildren + 4);

	for (int i = *(int*)StartOfChildren; i != EndOfChildren; i += 8)
	{
		if (memcmp(GetClass(*(int*)i), Name, strlen(Name)) == 0)
		{
			return *(int*)i;
		}
	}
}

uintptr_t SC;
uintptr_t SCDM;

void ScriptContextMethod()
{
	std::cout << "assing SCVFT..." << std::endl;
	auto _ScriptContext = aslr(0x2F02A2C); // ScriptContextVFTable Address
	std::cout << "Scan..." << std::endl;
	uintptr_t ScriptContext = Memory::Scan(PAGE_READWRITE, (char*)&_ScriptContext, (char*)"xxxx"); /* Scan for 'ScriptContextVFTable' Value */
	std::cout << "Output: " << ScriptContext << std::endl;
	SC = ScriptContext;
	std::cout << "Getting Parent of ScriptContext (DataModel)..." << std::endl;
	auto DM = RBXGetParent(ScriptContext);
	std::cout << "Output: " << DM << std::endl;
	std::cout << "Getting ScriptContext from DataModel (for testing)..." << std::endl;
	SCDM = FindFirstClass(DM, "ScriptContext");
	std::cout << "Output: " << SCDM << std::endl;
	std::cout << "If last output is same with the scan output then datamodel is valid." << std::endl;
}

void main()
{
	DWORD asdmemes;
	VirtualProtect((PVOID)&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &asdmemes);
	*(BYTE*)(&FreeConsole) = 0xC3;
	AllocConsole();
	SetConsoleTitleA("DataModel Scanner (SCMethod)");
	freopen("CONOUT$", "w", stdout);
	freopen("CONIN$", "r", stdin);
	HWND ConsoleHandle = GetConsoleWindow();
	::SetWindowPos(ConsoleHandle, HWND_TOP, 0, 0, 0, 0, SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
	::ShowWindow(ConsoleHandle, SW_NORMAL);
	ScriptContextMethod();
	//so after you get a valid datamodel then you can get a valid roblox lua state. all you need to do is a little bit of magic
	//to get valid rls we can use mellonyts dump for example:
	//auto RobloxLuaState = (RBX_LuaState(SCDM)); //this code can be wrong if doesnt work then use auto RobloxLuaState = (RBX_LuaState(SC));
	// [!] ok so we got the RLS but we cant use yet we need to use r_lua_newthread before using it but newthread function has been inlined so you can rewrite it urself if u have skills or you can just credit Rexi and use his lib. https://github.com/RexiRexii/Remade-Lua
	//after getting newthread function working now we can use: 
	//DWORD RLS = r_lua_newthread(RobloxLuaState);
	//Happy Exploiting! RLS is the valid rlua state for us to use

	//if you had any problems or wanna learn how to get scriptcontextvftable urself then DM me. Lumity#5626
	//credit me if you use this code. please note i dont made most part of this code but i dont know who made them too. if you know or if you are owner of a code used here then please contact me.
}


BOOL __stdcall DllMain(HINSTANCE Dll, DWORD Reason, LPVOID Reserved) {
	if (Reason == DLL_PROCESS_ATTACH) {
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)main, 0, 0, 0);
	}
	return TRUE;
}
