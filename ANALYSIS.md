# Steam CEG Anti-Tamper Bypass (Maintaining Anti-Piracy)
This write-up covers my research and implementation for bypassing specific anti-tamper functionality within Steam's CEG system, while preserving its anti-piracy checks. The goal was to remove limitations that interfered with reverse engineering, debugging, and hooking, without enabling unauthorized use.

## Why I Started
I began this research while attempting to hook a function that immediately caused the game to terminate. My initial assumption was that I had implemented the hook incorrectly, so I tried different offsets in the same function, all with the same result.
To investigate further, I used x32Dbg and set a byte hardware breakpoint on access at the address I was trying to hook. The breakpoint was instantly trigger and revealed an instruction at `0x637F4B` that was reading the byte:
```
mov eax, dword ptr ds:[esi]
```
Judging by the structure of the function that the instruction was in, it was most likely a CRC. I cross-referenced the function and confirmed it was a part of CEG, as all its references pointed to other known CEG functions. Knowing this, I labeled it `CEG_CalcMemoryCRC`

## Kill Switches
After setting a breakpoint on that CRC function and letting it run, I watched what used the result. I ended up just NOPing the call entirely and immediately got hit with a last chance exception for an access violation. The instruction that causes the violation is at address `0x8CF79B`
```
mov [eax], ecx
```
But just before that? A good old-fashioned:
```
xor eax, eax
```
A simple null pointer write. This was a CEG kill switch kicking in, a very simple one too. I labeled this one: `CEG_Killswitch_NullPtr`
Using IDA, I could now see several XREFs to both of these functions. Note that not all CEG functions are able to be viewed in static analysis, but these ones are.

This is not the only way CEG will try and end the process, however the rest of them are just as easy to find since CEG uses the usermode stubs for every syscall, meaning placing breakpoints on process-exiting syscalls is trivial. You don’t need to go kernel-deep to catch these, just put a breakpoint on ExitProcess or TerminateProcess, and you’ll hit if you trip CEG.
Setting breakpoints on
```
<kernel32.dll.ExitProcess>
<kernel32.dll.TerminateProcess>
```
was enough to stop the game from closing when tampering with CEG. However setting breakpoints here is only useful to realize you tripped CEG without actually having the process close. The problem is that CEG smashes the callstack and replaces it with `0x8000DEAD`
