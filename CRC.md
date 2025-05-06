# CEG_CalcMemoryCRC
For those curious, here are the registers used in `CEG_CalcMemoryCRC` (Latest Steam `t6sp.exe` binary, address `0x637F30`):

`EDI`: Total bytes to check

`ECX`: Base address of the region

`EDX`: Offset (starts at 0)

`EBP`: CRC lookup table

`EBX`: Byte currently being checked

Here is the function itself in IDA, with extra comments I left during my time researching

![alt text](https://github.com/Rattpak/CEG-Anti-Tamper-Analysis/blob/7a2b4dbfbaa0d4545ab5f5d32740e4cde247662d/img/ceg_calcmemorycrc.png "CEG_CalcMemoryCRC function in IDA with labeled registers")
