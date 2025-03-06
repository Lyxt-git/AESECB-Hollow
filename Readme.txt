Note : 
For Python Script, the Fileless Memory Injection works well, any payload injected are good (PoC), but to ensure the Target Architecture is better in making the payload works without interruption.
In this case, Python version injected with payload size allocated, BUT the function is abnormal, may consider to enhance the Reconnaissance about the target system architecture before actual pwned.

PoC with PE Studio, Process Hacker and WinDBG according to the Python (64bit Target).

    Step                                    Description
1️⃣ Select target process	                Ensure architecture matches your payload (32-bit/64-bit)
2️⃣ Prepare payload	                        Ensure it’s a valid PE file, obfuscate to bypass AV
3️⃣ Create process in suspended state	    Use CreateProcess() with CREATE_SUSPENDED
4️⃣ Get process information	                Retrieve handles & base address using PEB
5️⃣ Unmap original executable	            Use NtUnmapViewOfSection() to remove old image
6️⃣ Allocate & write payload	                Use VirtualAllocEx() and WriteProcessMemory()
7️⃣ Update entry point	                    Modify EAX in thread context to point to payload
8️⃣ Resume execution	                        Use ResumeThread() to execute payload

(This is a basic step in Fileless Memory Injection @ Process Hollowing).
