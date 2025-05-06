# CEG Anti-Tamper Analysis

Reverse engineering, analysis, and partial disabling of Steam's CEG (Custom Executable Generation) anti-tamper protections in `t6sp.exe` (Call of Duty: Black Ops II singleplayer), while **preserving all anti-piracy mechanisms**.

> ⚠️ **Disclaimer:** This project is for educational and research purposes only. It does **not** and will **never** facilitate piracy or unauthorized distribution of software. The focus is strictly on bypassing tamper protections to allow for legitimate reverse engineering, modding, and debugging workflows.


## Overview

This repository documents the process of identifying, analyzing, and partially neutralizing CEG’s anti-tamper functionality in `t6sp.exe`. The intent is to allow deeper understanding and modification of the binary for personal or research use, without impacting the core anti-piracy measures enforced by Steam.

## Analysis

For the full technical write-up, including debugger techniques, CRC bypass strategies, and notes on function structure and behavior:

[**Read the full analysis here**](ANALYSIS.md)


## Notes

- Focuses exclusively on `t6sp.exe` (Black Ops II SP).
- Preserves all anti-piracy checks.
- Does not contain or link to any copyrighted game files.
- Designed for experienced reverse engineers and hobbyists interested in software protection mechanisms.
