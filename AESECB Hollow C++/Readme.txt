Process Hollowing with AES Encryption (Pre-Compiled)

Overview
This project demonstrates Process Hollowing in C++ while incorporating AES encryption to obfuscate the payload. The program encrypts an executable file (Executor.exe), stores it as an encrypted binary file (Executor.enc), decrypts it in memory, and then injects it into a suspended 32-bit Notepad process.

Features
•	AES Encryption & Decryption using Crypto++
•	File Encryption: Encrypts Executor.exe into Executor.enc
•	Process Hollowing:
o	Launches a suspended 32-bit Notepad (OR any)
o	Allocates memory for decrypted payload
o	Writes decrypted payload into Notepad's memory
o	Modifies Notepad's execution context to run the injected payload

Prerequisites
Dependencies:
1.	Crypto++ Library (for AES encryption/decryption)
2.	Windows API (for process manipulation)

Compilation Requirements: (Ninja, GCC, G++)
•	Windows OS (32-bit target)
•	C++ Compiler with Windows API Support (MinGW, MSVC, etc.)
•	Crypto++ Headers and Libraries

File Structure
├── ObfuscationProject
│   ├── Executor.exe                 # Original executable (payload)
│   ├── Executor.enc                 # AES encrypted payload
│   ├── decrypted_payload.bin         # Decrypted binary for debugging
│   ├── main.cpp                      # Source code
│   ├── Readme.txt                    # This file

Note for Consideration, the Executor is demon.x86.exe, build from HavocC2, you may create your own payload as you wish)

Code Breakdown
1. Encryption of Executor.exe
•	Reads the Executor.exe file as bytes.
•	Encrypts it using AES-128 ECB Mode.
•	Writes the encrypted data into Executor.enc.

2. Decryption and Process Hollowing
•	Reads Executor.enc and decrypts it.
•	Saves the decrypted file temporarily for debugging.
•	Starts 32-bit Notepad in a suspended state.
•	Allocates memory inside Notepad’s process space.
•	Writes the decrypted payload into allocated memory.
•	Modifies Notepad’s execution context to jump to the injected payload.
•	Resumes execution, effectively replacing Notepad with the payload.

How to Use
1.	Compile the Code
  - g++ main.cpp -o ObfuscationProject.exe -lcryptlib -ladvapi32
2.	Run the Program
  - ObfuscationProject.exe
o	This will encrypt Executor.exe into Executor.enc.
o	It will then decrypt and inject it into a suspended Notepad process.

Security Considerations
•	This project is for educational and research purposes only.
•	Process Hollowing is often flagged by security software as malicious.
•	Run this in an isolated lab environment to avoid detection.
Legal Disclaimer
This code is provided strictly for educational purposes. Misuse of this technique for unauthorized access or malicious intent is illegal and not supported.
________________________________________

Author
•	Name: Berzerker
•	Project: C2 Framework Obfuscation using C++ (32-bit Target)

