////////////////////////////////////
//	In the end, this is all you need to disable
//	do disable most anti-tamper checks
//	without touching anti-piracy checks
////////////////////////////////////

//CEG_CalcMemoryCRC at 0x52C8FC
DWORD crc_jmpBackAddr;
void __declspec(naked) crcHook() {
	__asm {
		mov esi, ecx
		mov eax, 0xFFB97B1F
		mov[esi], eax
		jmp[crc_jmpBackAddr]
	}
}

void __declspec(naked) svHook() {
	__asm {
		mov eax, [esp]
		push eax

		mov eax, 0x4684E0
		call eax

		pop eax
		jmp eax
	}
}

//dont disable CEG entirely; Keep anti-piracy but remove anti-tamper
void CEG::setupCRCHooks() {
	HANDLE pHandle = GetCurrentProcess();

	/**Setting up CRC Hooks**/
	//this one protects the CEG_CalcMemoryCRC function itself
	//meaning once this is hook, we can do anything to fake CRC
	
	// No longer needed since the server thread hook is installed
	DWORD crcHookAddr = 0x52C8FC;
	crc_jmpBackAddr = crcHookAddr + 5;
	Hook::initHook((void*)crcHookAddr, crcHook, 5);

	/**Setting up stack pointer adjustment**/
	constexpr std::array<unsigned char, 3> ESP_PATCH = { 0x83, 0xC4, 0x0C };
	WriteProcessMemory(pHandle, (LPVOID)0x55A87C, ESP_PATCH.data(), ESP_PATCH.size(), nullptr);

	CEG::print("Setting up server thread hook");
	DWORD svHookAddr = 0x4CC4C0;
	Hook::initHook((void*)svHookAddr, svHook, 5);

	/**Setting up ESI instruction**/
	//This is the ESI patch discussed in the analysis documentation
	//add esi, 4 ------> mov esi, 1C0 + nop
	// Not used but here for reference
	constexpr std::array<unsigned char, 6> ESI_PATCH = { 0xBE, 0xC0, 0x01, 0x00, 0x00 , 0x90 };
	WriteProcessMemory(pHandle, (LPVOID)0x52C8E5, ESI_PATCH.data(), ESI_PATCH.size(), nullptr);

	/**Disabling SHA1 function checks**/
	//disable SHA1 checks
	Hook::nopMem((void*)0x87DFFA, 5);
	Hook::nopMem((void*)0x514D31, 5);

	/**Disabling .rdata table checks**/
	//disable the CRC .rdata table ones
	Hook::nopMem((void*)0x87E046, 5);
	Hook::nopMem((void*)0x5544AC, 5);
}
