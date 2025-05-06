# Steam CEG Anti-Tamper Bypass (Maintaining Anti-Piracy)
This write-up covers my research and implementation for bypassing specific anti-tamper functionality within Steam's CEG (Custom Executable Generation) system specifically for `t6sp.exe`, the singleplayer executable for *Call of Duty: Black Ops II*. The goal was to remove limitations that interfered with reverse engineering, debugging, and hooking, without enabling unauthorized use or affecting the game's built-in anti-piracy protections.

## Why I Started
I began this research while attempting to hook a function that immediately caused the game to terminate. My initial assumption was that I had implemented the hook incorrectly, so I tried different offsets in the same function, all with the same result.

To investigate further, I used x32dbg and set a byte hardware breakpoint on access at the address I was trying to hook. The breakpoint was instantly trigger and revealed an instruction at `0x637F4B` that was reading the byte:
```asm
mov eax, dword ptr ds:[esi]
```
Judging by the structure of the function that the instruction was in, it was most likely a CRC. I cross-referenced the function and confirmed it was a part of CEG, as all its references pointed to other known CEG functions. Knowing this, I labeled it `CEG_CalcMemoryCRC`

If you want to see the internals of this function, see [CRC.md](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/3d97b926d02e8a8a5fd95533349b8f377d63e97a/CRC.md)

## Kill Switches
After setting a breakpoint on that CRC function and letting it run, I watched what used the result. I ended up just NOPing the call entirely and immediately got hit with a last chance exception for an access violation. The instruction that causes the violation is at address `0x8CF79B`
```asm
mov [eax], ecx
```
But just before that? A good old-fashioned:
```asm
xor eax, eax
```
A simple null pointer write. This was a CEG kill switch kicking in, a very simple one too. I labeled this one: `CEG_Killswitch_NullPtr`

![alt text](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/238f13f634e75c763b70a05c4b4aca7bd1594bce/img/nullptr.png "CEG_Killswitch_NullPtr in IDA")

Using IDA, I could now see several XREFs to both of these functions. Note that not all CEG functions are able to be viewed in static analysis, but these ones are.

Since this function was still CEG protected, I hooked memcpy instead, and ran a valid memory check like this:

```C++
bool isMemoryReadable(const void* address, size_t size) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
		return false;
	}
		
	DWORD protect = mbi.Protect;
	bool readable = (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) || (protect & PAGE_EXECUTE_READ) || (protect & PAGE_EXECUTE_READWRITE);
	return readable && ((uintptr_t)address + size <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize);
}

void* _memcpy_hookfunc(void* a1, const void* Src, size_t Size) {
	if (!isMemoryReadable(Src, Size)) {
		/**memcpy Kill Attempt Prevented**/
		return a1;
	}

	return memcpy(a1, Src, Size);
}
```

Which did work, but this is not the only way CEG will try and end the process, however the rest of them are just as easy to find since CEG uses the usermode stubs for every syscall, meaning placing breakpoints on process-exiting syscalls is trivial. You don’t need to go kernel-deep to catch these, just put a breakpoint on ExitProcess or TerminateProcess, and you’ll hit if you trip CEG.
Setting breakpoints on
```
<kernel32.dll.ExitProcess>
<kernel32.dll.TerminateProcess>
```
was enough to stop the game from closing when tampering with CEG. However setting breakpoints here is only useful to realize you tripped CEG without actually having the process close. The problem is that CEG smashes the callstack and replaces it with `0x8000DEAD`

Here is what the callstack will look like when setting a breakpoint on exit syscalls:

![alt text](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/0bcb9d1403ae6635b5a0b2a3266432250c8fb679/img/callstack.png "Example of the callstack being destroyed")

Heres some code of it:

![alt text](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/fbb35e94a7e9792997fea5e5ac2353739d3f221e/img/ceg_exitprocess.png "The CEG_ExitProcess function in IDA")

This is not the only location that the `0x8000DEAD` occurs, so its not at simple as removing that part of the function. However, I found the function responsible for this stack smashing and wrote a hook that logs the thread ID and suspends the thread before it can even get to ExitProcess. It worked, and was kind of fun to implement and was very usefull. I eventually scrapped it because again, I wasn’t trying to make a full CEG disabler, I just wanted my hooks to stop triggering kill switches. So at this point my research into CEG killswitches was done.

## Attempting to Spoof the CRC
My first idea for the CRC function was to basically gut it and replace its internals with a stub function that takes in the requested CRC start address, and from there, just returns whatever the expected CRC would be. While I still believe this is a viable approach, it didn’t seem practical at the time, especially since I was still deep in the research phase, trying to understand how everything actually worked.

There are also other complications. For example, `CEG_CalcMemoryCRC` can take the same parameters but yield different CRC results depending on the value in ESI before the function is called. Now I did experiment with this a bit and found a way to force ESI to always be the same. By changing the 
```asm
add esi, 4
```
in the loops where `CEG_CalcMemoryCRC` is called to
```asm
mov esi, 0x1C0
```
it will still pass all the CRC checks that are needed to keep CEG happy and the game running, while only doing about 1/5 the amount of checks. In the end i did not end up using this trick, but it was still interesting to see.

## Hooking Time
So when I went to modify the internals of the `CEG_CalcMemoryCRC` function, it immediately tripped CEG. A CRC that checks itself. Very nice. Setting a hardware breakpoint inside the function revealed that there was one specific call that would check it, but interestingly, that call itself wasn’t protected by a CRC.

Since this was the first CRC I started working on for CEG, I set a breakpoint at the end of the CRC calculation, grabbed the value in `EAX`, and made a hook that jumps to a custom function. That function emulates the CRC setup and then just force-returns the correct result.
```C++
void __declspec(naked) crcHook() {
	__asm {
		mov esi, ecx
		mov eax, 0xFFB97B1F ;<-------- CRC value
		mov[esi], eax
		jmp[crc_jmpBackAddr]
	}
}
```

Replacing the CRC call here with my hook worked perfectly for what I needed. It gave me full freedom to modify the internals of the CRC function as much as I wanted, which was extremely useful, both for analysis and for seeing exactly what chunks of memory were being checked.

One important thing to note: CEG doesn't just check the specific function it's interested in. Instead, it checks thousands of bytes before and after. The original function I was trying to hook wasn’t even a CEG function, but it still got caught in the crossfire of a broader CEG memory check.

## More CRC Checks

However, this wasn’t the only function that checked the CRC function, there were others. Fortunately, the rest weren’t called every frame. Instead, they only ran under specific conditions (like level changes and client disconnects). One of those additional checks is called from a function that scans hundreds of other functions, so a simple one-value spoof wasn’t going to cut it.

**Note:** This list just lists the name of the function where the start addresses of the CRC checks, and does not contain the functions that are inside the CRC checks.
```
CEG CRC Integrity Check Locations

//Functions
Actor_Pain
AimAssist_RegisterDvars
CG_CompassCalcDimensions
CG_SndEntHandle
CG_UpdateClouds
CycleWeapPrimary
DB_PrintXAssetsForType_FastFile
Dvar_Init
Dvar_IsValidName
Expression_MapIndexToFunction
hks::Visitor::visit_children (the one at 0x6009A0)
IPak_AddPackfile
LiveLeaderboard_GetByPlayer
LiveSteam_PopOverlayForSteamID
Live_UpdatePlayerNetAddr
Menu_Paint
mp_reduce_2k_l
OrientationInvert
Party_Init
PlayerCmd_meleeButtonPressed
ReadPathNodes
Scr_Vehicle_Think
SEH_LocalizeTextMessage
SP_info_vehicle_node
VEH_UpdateNitrousPosition
VEH_UpdatePathOffset
SpotLightViewMatrix
standard_query::query
Turret_PlaceTurret_UpdateFooting
(many many more)
```

For now, I’ll refer to this function as the main CRC checking function and for good reason. The parent function (which contains both the CRC I hooked and this "main CRC check") is called from two separate places: `SV_PreFrame_Save` and `SV_ServerThread`. Internally, it intercepts the call to `SV_ProcessPendingSaves`. I named this CRC checker `CEG_SV_RunMemoryCRC`.

This function runs every server frame. You could nop out the call in both `SV_ServerThread` and `SV_PreFrame_Save`, and that would work, but it would also break the entire savegame system.

Also worth noting: `SV_ProcessPendingSaves` has no XREFs. That’s because CEG doesn’t call it directly. Instead, it gets the function address manually, stores it in EAX, jumps to it, and pushes the original return address (from either `SV_ServerThread` or `SV_PreFrame_Save`) into the stack pointer.
The solution was actually pretty straightforward: just replace the `CEG_SV_RunMemoryCRC` call with a direct call to `SV_ProcessPendingSaves`. However, that didn’t work immediately, because EAX no longer held the correct value, meaning the jump landed somewhere random in memory.

![alt text](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/59257d56c04dc43cff72c2cfb63df4d7d5e89dc2/img/CEG_SV_ProcessPendingSaves.png)

Anyway, the good news is, we don’t actually need that indirect jump via EAX anymore, since we already control the hook. So we can just jump out of the hook directly to where we want.

Here’s the simple assembly I threw together to make that work:

```C++
void __declspec(naked) svHook() {
	__asm {
		mov eax, [esp] ;<------ the address of the location to jump back to
		push eax

		mov eax, 0x4684E0 ;<------ address of actual SV_ProcessPendingSaves
		call eax

		pop eax
		jmp eax
	}
}
```

This code worked perfectly when the function was called from `SV_ServerThread`, but caused issues when it was called from `SV_PreFrame_Save`. Setting a breakpoint and letting it run revealed a glaring issue: the stack pointer needed to be adjusted differently now that we were no longer going through the original CEG functions.

In the debugger, I noticed that `ESP + 8` now contained `00000001`, which was clearly wrong. The value we actually wanted was now sitting at `ESP + 0xC`.

![alt_text](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/ba79aac125a58a9069e4f1e250cf5d920fc5417d/img/esp_adjust.png "")

So, changing:

```asm
add esp, 8
```
to:
```asm
add esp, 0xC
```
inside `SV_PreFrame` completely resolved the issue.

Interestingly, this new bypass made my original CRC hook obsolete. Still, that hook was extremely useful for understanding how everything fit together.

## What's Left?
With this "main CRC" function knocked out, you can now freely edit a ton of other stuff that you couldn’t touch before. If you set a breakpoint inside the CRC function, you’ll still see checks happening, but they’re a lot less frequent and cover far less variety. Since the functions that call it aren’t likely being checked anymore, you can knock out a few easy ones without any real concern.

There are also CRC checks targeting .rdata (possibly for the CRC result table?) I haven’t looked into that part too deeply. I labeled that one `CEG_CheckRdata`, and you can nop it out without any problems. Same thing goes for another CRC function that protects a CEG SHA1 routine, easy to remove.

With those out of the way, you’re left with very, very few functions that still run CRC checks. But honestly, none of them are checking anything I’d consider remotely useful. And with the main protections already disabled, you could easily patch over the remaining checks using a simple hook like the ones I showed earlier.

## Conclusion
Overall, disabling the anti-tamper checks only took me a couple of hours in total, though that was spread out over several days, just working on it here and there. The bulk of the time was spent doing reconnaissance on how CEG works internally.
**Importantly, this doesn’t mess with any of the anti-piracy protections**. I stayed away from that on purpose.
There were a ton of smaller techniques and analysis methods I used along the way that I either don’t remember clearly or don’t care to detail here, since they’re kind of outside the scope of this write-up anyway.
I’ll probably revisit this again at some point just for fun, and maybe try coming up with a completely different solution.

Also, since CEG is entirely usermode, it makes for a really fun and approachable playground if you’re interested in getting into reverse engineering or tamper protection bypassing in games. No kernel-mode trickery needed, just you, your debugger, and a lot of curiosity.

During the early phases of research, the code was fairly chaotic. Hooks were scattered everywhere, and it felt like I was playing whack-a-mole with kill switches and integrity traps. But as I learned more about the flow and structure of CEG, everything started to converge and streamline. In the end, thanks to some architectural weaknesses in CEG (e.g., reliance on usermode stubs, predictable call structures, and some important functions not CRC checked), the final code ended up being much smaller and less complex than I initially expected.

If you would like to look at the final product source code, see [anti-anti-tamper.cpp](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/f1bfb4025c7a1caa929053bea675d9c86b66b622/code/anti-anti-tamper.cpp)
