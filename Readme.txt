Note : (Both Base Code are Pre-Compiled)
- For Python Script, the Fileless Memory Injection works well, any payload injected are good (PoC), but to ensure the Target Architecture is better in making the payload works without interruption.
  In this case, Python version injected with payload size allocated, BUT the function is abnormal, may consider to enhance the Reconnaissance about the target system architecture before actual pwned.

PoC with PE Studio, Process Hacker and WinDBG according to the Python (64bit Target).

    Step                                    Description
1️⃣ Select target process	            Ensure architecture matches your payload (32-bit/64-bit)
2️⃣ Prepare payload	                    Ensure it’s a valid PE file, obfuscate to bypass AV
3️⃣ Create process in suspended state	    Use CreateProcess() with CREATE_SUSPENDED
4️⃣ Get process information	            Retrieve handles & base address using PEB
5️⃣ Unmap original executable	            Use NtUnmapViewOfSection() to remove old image
6️⃣ Allocate & write payload	            Use VirtualAllocEx() and WriteProcessMemory()
7️⃣ Update entry point	                    Modify EAX in thread context to point to payload
8️⃣ Resume execution	                    Use ResumeThread() to execute payload

(This is a basic step in Fileless Memory Injection @ Process Hollowing). You may get the based code and re-design your own cryptology method, here is AES-ECB which to be consider as insecure.
Insecure means, to crack it is easy ...

/* Additional Information */

Explanation of AES-ECB
    - AES (Advanced Encryption Standard) is a symmetric encryption algorithm. The project uses AES-128 ECB Mode, which operates as follows:
        •	ECB (Electronic Codebook) mode encrypts each block of plaintext independently.
        •	Pros:
            o	Simple to implement
            o	Fast encryption process
        •	Cons:
            o	Not secure for large data as identical plaintext blocks produce identical ciphertext.
            o	No IV (Initialization Vector) makes it susceptible to pattern analysis.

Better alternatives:
    •	AES-CBC (Cipher Block Chaining): Uses an IV for randomness.
    •	AES-GCM (Galois/Counter Mode): Provides both encryption and authentication.

Process Hollowing & Alternative Techniques
Process Hollowing replaces the memory of a legitimate process with a malicious payload. However, other more advanced injection techniques include:
    1.	Process Doppelgänging:
        o	Uses NTFS transactions to run a malicious process without writing to disk.
        o	Bypasses most traditional security solutions.
    2.	Thread Hijacking:
        o	Injects code into an existing thread of a running process.
    3.	Reflective DLL Injection:
        o	Loads a DLL into memory without registering it with the OS.

Security Considerations
    •	This project is for educational and research purposes only.
    •	Process Hollowing is often flagged by security software as malicious.
    •	Run this in an isolated lab environment to avoid detection.

Legal Disclaimer
This code is provided strictly for educational purposes. Misuse of this technique for unauthorized access or malicious intent is illegal and not supported.
________________________________________________________________________________________________________________________________________________________________

Author
•	Name: Berzerker
•	Project: C2 Framework Obfuscation using Python & C++ (Windows Target)

