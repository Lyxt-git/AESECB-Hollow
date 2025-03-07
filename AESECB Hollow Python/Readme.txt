Process Hollowing with AES Encryption (Python Version) - (Pre-Compiled)

Overview
This project demonstrates Process Hollowing in Python while incorporating AES encryption to obfuscate the payload. The program encrypts an executable file (Executor.exe), stores it as an encrypted binary file (Executor.enc), decrypts it in memory, and then injects it into a suspended Notepad process.

Features
•	AES Encryption & Decryption using PyCryptodome
•	File Encryption: Encrypts Executor.exe into Executor.enc
•	Process Hollowing:
o	Launches a suspended Notepad process
o	Allocates memory for the decrypted payload
o	Writes decrypted payload into Notepad's memory
o	Modifies Notepad's execution context to run the injected payload

Prerequisites
Dependencies:
  1.	PyCryptodome (for AES encryption/decryption)
  2.	Pywin32 (for Windows API process manipulation)
  3.	Psutil (for process management)

Installation:
Run the following command to install the required dependencies:
pip install pycryptodome pywin32 psutil

File Structure
├── ObfuscationProject
│   ├── Executor.exe                 # Original executable (NOTE : This original payload build from HavocC2, should use your own payload as you wish)
│   ├── Executor.enc                 # AES encrypted payload
│   ├── Hollowed.py                  # Source code
│   ├── Readme.txt                   # This file

Code Breakdown
  1. Encryption of Executor.exe
    •	Reads the Executor.exe file as bytes.
    •	Encrypts it using AES-128 ECB Mode.
    •	Writes the encrypted data into Executor.enc.
  2. Decryption and Process Hollowing
    •	Reads Executor.enc and decrypts it.
    •	Starts Notepad in a suspended state.
    •	Allocates memory inside Notepad’s process space.
    •	Writes the decrypted payload into allocated memory.
    •	Modifies Notepad’s execution context to jump to the injected payload.
    •	Resumes execution, effectively replacing Notepad with the payload.

How to Use
  1.	Run the Program
    python main.py
      o	This will encrypt Executor.exe into Executor.enc.
      o	It will then decrypt and inject it into a suspended Notepad process.

Security Considerations
  •	This project is for educational and research purposes only.
  •	Process Hollowing is often flagged by security software as malicious.
  •	Run this in an isolated lab environment to avoid detection.

Legal Disclaimer
- This code is provided strictly for educational purposes. Misuse of this technique for unauthorized access or malicious intent is illegal and not supported.
________________________________________
Author
•	Name: Berzerker
•	Project: C2 Framework Obfuscation using Python (Windows Target)

