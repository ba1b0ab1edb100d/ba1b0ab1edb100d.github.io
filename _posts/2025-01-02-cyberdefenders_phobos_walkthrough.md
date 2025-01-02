---
title: CyberDefenders Phobos Lab Walkthrough
date: 2025-01-02 16:41:00 +/-TTTT
categories: [Malware Analysis, Reversing]
# tags: [TAG]     # TAG names should always be lowercase
media_subpath: /assets/cyberdefenders_phobos/
---
### Foreword
To avoid constant referencing and repetition, let me introduce the `sub_406347` function, referred to as `decrypt` from here on. It's quite straightforward to detect this function (and generally, similar functions are often easy to spot). We start by identifying the function with numerous cross-references:

![decrypt function](1.png)

Then, simply set a breakpoint in the debugger and check what it returns. You get a pointer to a string.

During the analysis, you'll encounter the `sub_403BB3` function, which also decrypts data. This can be deduced from the returned value and the similarity of the parameters passed to these two functions:

![another decrypt function](2.png)

Let's move on to the questions.

### 1. Understanding which hashing algorithm is used by the malware helps understand how the malware functions. What is the hashing algorithm used by the malware?

You can search for encryption algorithms manually by looking for specific patterns — such as loops, blocks, hardcoded values, etc. Alternatively, you can save time by using plugins/utilities, whatever you prefer. To start, you might use `YARA` rules to search for known patterns. For this, I'll use the `DiE` utility, which offers such functionality.

![utility output](3.png)

### 2. Following up on the previous question. Could you provide the hard-coded value of the `.cdata` checksum?

Once the algorithm, addresses, and constants from the first question are identified, you can locate the function used for hashing. Lets name it `crc_tab`

![crc32 function](4.png)

As you can see, the data is taken from the `ECX` register. Therefore, it makes sense to investigate further in this direction.

![crc32 params](5.png)

The data in `ECX` comes from `ESI`, and it is sourced to `ESI` from `dword_40B408`:

![encryption cdata](6.png)

Therefore, `ESI` is equal to the address `dword_40b408 (40b408)` plus the value stored at that address `(3bf8)`. `40b408` + `3bf8` = `40f000`. The result is `40f000`, which represents the start of the `.cdata` section.

![encryption cdata](7.png)

Right after the hashing function, there's a check against `dword_40b430`. If this check fails, the program terminates. This implies that the program verifies the integrity of the encrypted data before execution. The hash value of the intact data must be equal to `0d55f8833`.

![constant of cdata hash](8.png)

### 3. Different malware versions may be linked to specific cybercriminal groups or campaigns, thus providing valuable leads for your threat intel analysts. What is the malware's version?

As we go through each function and analyze them one by one, we'll encounter the function `sub_4028CA`. What makes it interesting? It contains a hardcoded string `"ID"` and the `decrypt` function.

![id and decrypt](9.png)

Let's see what the debugger reveals. Set a breakpoint on the decryption function and examine the result:

![decrypts id result](10.png)

Here, we see `v2.9.1`, but since the string is hardcoded, this version cannot refer to any data collected from the host, etc. Therefore, `v2.9.1` is the version of this sample.

### 4. Malware sometimes masquerades as legitimate DLL files to bypass standard security measures and evade detection. Identifying which legitimate DLL a malware is impersonating allows for more accurate and effective detection mechanisms. Could you provide the name of the legitimate DLL that the malware is masquerading as?

This task can be solved both statically and dynamically. Dynamically, you can simply load it into a sandbox and try to retrieve information about all created files. The advantage of this approach is quick information gathering; the drawback is that the malware might have anti-sandbox features, causing the program to crash without dropping any files. Therefore, I prefer static analysis to eliminate suspicions and avoid triggers.

Statically, you can also try different approaches. For example, the imports include the `CreateFileW` function, and you can set a breakpoint on it to inspect the filename parameter passed to it. In my case, I fully dissect the malware, so not far from the program's start, I encounter a block with the function:

![block with dll drop function](11.jpg)

Inside it, `CreateThread` is called. I examine such functions more thoroughly, especially since this is the first function (and there will be many) that makes this `API` call.

If a part of the ransomware masquerades as an executable file, it either injects itself somewhere or creates a file and then executes it. Here, there are indeed some intriguing calls:

![writefile and createfile in first thread](12.png)

Set a breakpoint on the preceding call to the decrypt function, which is located right before `CreateFileW`, and obtain the signature of the executable file:

![MZ decrypt](13.png)

Continuing along the execution graph within the same function, not far from `WriteFile` and `CreateFile`, we encounter the function `sub_404325`:

![sub_404325](14.png)

At first glance, it seems uninteresting, but examining the functions it calls reveals that the program attempts to locate a file (`FindNextFileW`, `FindClose`, `FindFirstFileW`):

![sub_404325 finding file](15.png)

Let's dive into `sub_404325` and examine exactly what it is searching for. At the very beginning, a string gets decrypted, but why does it need `ole32.dll`? This is indeed more intriguing.

![ole32.dll string decrypt](16.png)

Let's delve into the function that iterates over the files (`sub_405d61`), and what we observe on the output is as follows (see the `ESI` and `ESP` registers):

![decrypted .net and ole32.dll strings](17.png)

So far, the program hasn't created any files; it was merely searching for a valid folder with `Microsoft.NET`. However, it's easy to be misled here: there are no calls to `CreateFile` or `WriteFile`. So, why did the program need this string with the `.NET FRAMEWORK` folder and the legitimate `ole32.dll`? The crux lies in the `OleGetObject` function and the `riid` that is passed to it. I debug such functions more thoroughly. Break on `OleGetObject`

![OleGetObject](18.png)

Let's google what the `riid` parameter is responsible for that is passed in the call shown in the screenshot above.

![OleGetObject riid](19.png)

There's no point in dissecting each call within `OleGetObject`, so  press `Step Out` and check the specific folder with the `.NET Framework`. After the function, a file named `ole32.dll` appeared there.

![ole32.dll created](20.png)

### 5. It is important to understand what this malicious DLL is used for and how it works. Could you analyze it and provide the first API function it calls?

Based on the previous analysis, we can load this `ole32.dll` into a disassembler and observe that this program only calls two `WinAPI` functions, the first of which is `CreateProcessW`.

![ole32.dll disassembled](21.png)

### 6. In ransomware attacks, the malware often terminates any processes that might disrupt its encryption before starting. Could you provide the address at which the process list decryption function is called?

We can often rely on specific `WinAPI` calls in this context. To terminate specific processes, it's necessary to know which processes are currently running. This is typically achieved through a process enumeration sequence using functions like `CreateToolhelp32Snapshot` -> `Process32FirstW` -> `Process32NextW`. Let's examine the function that employs them.

![proc shutdown function](22.png)

Let's check from where this function is being called - `sub_4022ee`.

![proc shutdown function xref](23.png)

Let's see what gets returned in the `decrypt` functions.

![proc decrypt](24.png)

The decryption function itself is called at the address `004022fb`.

### 7. Malware often disables and turns off the security settings part of the victim's machine to avoid detection and stay under the radar. What's the first command the malware uses to turn off a critical security measure?

This task can also be solved both statically and dynamically (using a sandbox). Here, the dynamic approach would be simpler.

However, since we've decided to use only a disassembler and a debugger, the second option will be briefly explained at the end of this response. Let's start with the static analysis.

As you continue through the sample, you may discover small blocks like these:

![example of blocks](25x26.jpg)

The function takes only one parameter, which closely resembles what the `decrypt` function accepts. Let's take a closer look inside.

![inside blocks func](27.png)

The sole argument is passed directly into the `decrypt` function, which looks intriguing. Let's make our lives easier and use a debugger. Set a breakpoint on the function and observe the result.

![vsadmin delete](28.png)

But this isn't what we need; we're looking for the disable security options, not the removal of shadow copies. Let's move on and examine other calls to this function.

![netsh](29.png)

This is exactly what we need. Since there are no separators and the commands are separated by a newline character `\n`, the first command will be `netsh advfirewall set currentprofile state off`.

### 8. Malware that successfully establishes a foothold and persistence can cause long-term damage by maintaining a presence on the infected system, allowing for continuous data theft, further infections, or other malicious activities. Could you provide the address of the function used by the malware for this purpose?

The first thing that comes to mind about this topic is various registry keys, so let's find where the `RegOpenKeyExW` function is being called from.

![regopenkey xrefs](30.png)

I dive into the very first function and set a breakpoint on `RegOpenKeyExW` to check the parameters being passed to it.

![regopenkey params](31.png)

On the stack, there's a string that helps us confirm the purpose of the function, identified as `sub_401236`.

### 9. Knowing how the malware communicates with its command and control (C2) server for data transmission is vital for understanding the threat's capabilities and potential reach. What protocol is used by the malware for C2 communication to transmit the data?

It's enough to look into the imports, find the `WINHTTP` library there, check the `POST` parameter, and determine where the functions from this library are being called.

![winhttp calls](32.png)

Go one level up and notice that the packet will contain the string `"ID"`, which malware assigned to the computer. So the answer is `http`.

![packet creation and params](33.png)

### 10. We need to understand further how the malware interacts with system hardware, how it monitors the system environment, and how it extends its reach. Could you provide the address of the thread used to check continuously for new disk connections?

If it's about system hardware, the first thing that stands out in the import section is the `GetLogicalDrives` function.

![getlogicaldrivers xrefs](34.png)

Only three functions. In two of them, it's called just once at the very beginning:

![getlogicaldrivers first func](35.png)

![getlogicaldrivers second func](36.png)

However, in the last one, you can see that it's called twice within the function, with one of the calls being inside a loop.

![getlogicaldrivers loop](37.png)

From the C-like pseudocode, we can infer that this function is responsible for monitoring new devices since each new result from `GetLogicalDrives()` is compared with the previous one, and this runs every `1000` (`0x3E8u`) milliseconds, or every second. Therefore, the answer is `00401cc5`.

### 11. The malware appears to be using different functions to encrypt small and large files. A check is performed before each encryption. The file size is compared to a specific value. Could you provide this value?

If the malware encrypts large and small files separately, there is likely a threshold to determine the size, and the software would need to know the file's size. Let's check the `GetFileSize` function in the imports.

![getfilesize xrefs](38.png)

The only function is `sub_408ebe`. Let's examine the `FileSize` parameter:

![getfilesize call](39.png)

Ultimately, it ends up in the variable `var_18`. Then there's a check against `180000`, which seems to be exactly what we need.

![param for file sizes](40.png)

Let's these functions (`sub_408c42` and `sub_408782`) that are called after the check.

![first crypt func](41.png)

![first crypt func](42.png)

To get a complete picture, you can set a breakpoint in the debugger to confirm that these are indeed the two functions for encryption. Therefore, the threshold is `180000`.
