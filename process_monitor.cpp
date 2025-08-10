#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <thread>
#include <conio.h>
#include <fstream> // Loglama için ekleme
#include <sstream>
#include <map>
#include <regex>

#pragma comment(lib, "psapi.lib")

void ShowAverageUsage(const std::wstring& exeName)
{
    std::wifstream logFile("process_log.txt");
    if (!logFile.is_open())
    {
        std::wcerr << L"Log dosyası açılamadı.\n";
        return;
    }

    std::wstring line;
    std::wregex logPattern(L"^(\\S+)\\s+(\\d+)\\s+([\\d.]+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)$");
    std::map<std::wstring, std::vector<double>> usageData;

    while (std::getline(logFile, line))
    {
        std::wsmatch match;
        if (std::regex_match(line, match, logPattern))
        {
            std::wstring name = match[1];
            double cpuUsage = std::stod(match[3]);
            DWORD ramUsage = std::stoul(match[4]);

            if (name == exeName)
            {
                usageData[name].push_back(cpuUsage);
                usageData[name].push_back(static_cast<double>(ramUsage));
            }
        }
        else
        {
            std::wcerr << L"Line did not match pattern: " << line << std::endl;
        }
    }

    logFile.close();

    auto it = usageData.find(exeName);
    if (it != usageData.end() && !it->second.empty())
    {
        double totalCpu = 0.0;
        double totalRam = 0.0;
        size_t count = it->second.size() / 2;

        for (size_t i = 0; i < count; ++i)
        {
            totalCpu += it->second[2 * i];
            totalRam += it->second[2 * i + 1];
        }

        double avgCpu = totalCpu / count;
        double avgRam = totalRam / count;

        std::wcout << L"\n" << exeName << L" için Ortalama Kullanım:\n";
        std::wcout << L"Ortalama CPU Kullanımı (%): " << avgCpu << L"\n";
        std::wcout << L"Ortalama RAM Kullanımı (MB): " << avgRam << L"\n";
    }
    else
    {
        std::wcout << L"Uygulama bulunamadı.\n";
    }
}




const std::set<std::wstring> criticalApplications = {
    L"SecurityHealth", L"svchost.exe", L"MsMpEng.exe", L"winlogon.exe", L"csrss.exe",
    L"smss.exe", L"lsass.exe", L"services.exe", L"spoolsv.exe", L"explorer.exe",
    L"dwm.exe", L"taskhostw.exe", L"SearchIndexer.exe", L"ctfmon.exe", L"conhost.exe",
    L"audiodg.exe", L"wuauserv.exe", L"wininit.exe", L"System", L"Idle", L"msiexec.exe",
    L"lsm.exe", L"mmc.exe", L"Realtek", L"RTHDVCPL", L"RtkAudUService", L"igfxtray.exe",
    L"igfxpers.exe", L"hkcmd.exe", L"SynTPEnh.exe", L"SYNTP", L"SYNTPHelper",
    L"rundll32.exe", L"cmd.exe", L"powershell.exe", L"powershell_ise.exe", L"regedit.exe",
    L"taskmgr.exe", L"calc.exe", L"mstsc.exe", L"sihost.exe", L"LocationNotificationWindows.exe",
    L"SearchHost.exe", L"StartMenuExperienceHost.exe", L"RuntimeBroker.exe", L"DllHost.exe",
    L"TextInputHost.exe", L"SecurityHealthSystray.exe", L"ArcControlAssist.exe",
    L"HostAppServiceUpdater.exe", L"ApplicationFrameHost.exe", L"ShellExperienceHost.exe",
    L"SystemSettingsBroker.exe", L"smartscreen.exe", L"backgroundTaskHost.exe"
};

bool GetProcessUserName(DWORD processID, std::wstring& userName)
{
    HANDLE hToken;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (!hProcess)
        return false;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProcess);
        return false;
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);
    if (tokenInfoLength == 0)
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    std::vector<BYTE> tokenInfo(tokenInfoLength);
    if (!GetTokenInformation(hToken, TokenUser, tokenInfo.data(), tokenInfoLength, &tokenInfoLength))
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    SID_NAME_USE sidType;
    wchar_t userNameBuf[256];
    wchar_t domainNameBuf[256];
    DWORD userNameSize = sizeof(userNameBuf) / sizeof(userNameBuf[0]);
    DWORD domainNameSize = sizeof(domainNameBuf) / sizeof(domainNameBuf[0]);

    if (!LookupAccountSid(NULL, ((TOKEN_USER*)tokenInfo.data())->User.Sid, userNameBuf, &userNameSize, domainNameBuf, &domainNameSize, &sidType))
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    userName = userNameBuf;
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}

bool IsCriticalApplication(const std::wstring& exeName)
{
    return criticalApplications.find(exeName) != criticalApplications.end();
}

void PrintProcessInfo(const PROCESSENTRY32& pe32, bool isUserProcess, bool isCritical)
{
    std::wcout << std::left
        << std::setw(35) << pe32.szExeFile
        << std::setw(10) << pe32.th32ProcessID
        << (isUserProcess ? L"User" : L"System")
        << (isCritical ? L" (Critical)" : L"")
        << std::endl;
}

double CalculateCPUUsage(const FILETIME& prevKernelTime, const FILETIME& prevUserTime,
    const FILETIME& kernelTime, const FILETIME& userTime,
    ULONGLONG prevTime, ULONGLONG currentTime)
{
    ULARGE_INTEGER kernel, user, prevKernel, prevUser;
    kernel.LowPart = kernelTime.dwLowDateTime;
    kernel.HighPart = kernelTime.dwHighDateTime;
    user.LowPart = userTime.dwLowDateTime;
    user.HighPart = userTime.dwHighDateTime;
    prevKernel.LowPart = prevKernelTime.dwLowDateTime;
    prevKernel.HighPart = prevKernelTime.dwHighDateTime;
    prevUser.LowPart = prevUserTime.dwLowDateTime;
    prevUser.HighPart = prevUserTime.dwHighDateTime;

    ULONGLONG deltaKernelTime = kernel.QuadPart - prevKernel.QuadPart;
    ULONGLONG deltaUserTime = user.QuadPart - prevUser.QuadPart;
    ULONGLONG timeInterval = currentTime - prevTime;

    if (timeInterval == 0 || (deltaKernelTime + deltaUserTime) == 0)
        return 0.0;

    double cpuUsage = 100.0 * (deltaKernelTime + deltaUserTime) / (timeInterval * 10000.0);

    return cpuUsage;
}

bool IsValidCPUUsage(double cpuUsage)
{
    return cpuUsage >= 0.0 && cpuUsage <= 100.0;
}

void LogProcessInfo(const std::wstring& exeName, DWORD processID, double cpuUsage, DWORD ramUsage, ULONGLONG diskRead, ULONGLONG diskWrite)
{
    std::wofstream logFile("process_log.txt", std::ios_base::app);
    if (logFile.is_open())
    {
        logFile << std::left
            << std::setw(35) << exeName
            << std::setw(10) << processID
            << std::fixed << std::setprecision(2)
            << std::setw(18) << cpuUsage
            << std::setw(10) << ramUsage
            << std::setw(15) << (diskRead / (1024 * 1024)) // MB
            << std::setw(15) << (diskWrite / (1024 * 1024)) // MB
            << std::endl;
        logFile.close();
    }
}

void ListProcesses(bool showUserProcesses, bool showCritical)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateToolhelp32Snapshot failed.\n";
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        std::cerr << "Process32First failed.\n";
        CloseHandle(hProcessSnap);
        return;
    }

    std::cout << "Processes:\n";
    std::cout << "Name                                PID    Type\n";
    std::cout << "----------------------------------------\n";

    std::vector<PROCESSENTRY32> processes;
    do
    {
        std::wstring userName;
        bool isUserProcess = GetProcessUserName(pe32.th32ProcessID, userName);
        bool isCritical = IsCriticalApplication(pe32.szExeFile);

        if ((showUserProcesses && isUserProcess) || (!showUserProcesses && !isUserProcess))
        {
            if ((showCritical && isCritical) || (!showCritical && !isCritical) || !showUserProcesses)
            {
                PrintProcessInfo(pe32, isUserProcess, isCritical);
                processes.push_back(pe32);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    if (showUserProcesses && !showCritical)
    {
        std::cout << "\nMonitoring CPU, RAM, and Disk I/O usage...\n";
        auto lastUpdate = std::chrono::steady_clock::now();

        std::vector<FILETIME> prevKernelTimes(processes.size(), { 0, 0 });
        std::vector<FILETIME> prevUserTimes(processes.size(), { 0, 0 });
        ULONGLONG prevTime = GetTickCount64();

        bool firstUpdate = true;
        bool secondUpdate = false;

        while (true)
        {
            auto now = std::chrono::steady_clock::now();
            std::chrono::duration<double> elapsed = now - lastUpdate;

            if (_kbhit())
            {
                char ch = _getch();
                if (ch == '0')  // Menüyü göstermek için '0' tuşuna basılması gerekiyor
                {
                    break;  // Döngüden çık ve menüye dön
                }
            }

            if (elapsed.count() >= 5.0) // Update every 5 seconds
            {
                if (firstUpdate)
                {
                    std::cout << "Waiting for valid data...\n";
                    firstUpdate = false;
                    secondUpdate = true; // Allow data display on the second update
                }
                else
                {
                    std::cout << "\nName                                PID    CPU Usage (%)  RAM Usage (MB)  Disk Read (MB)  Disk Write (MB)\n";
                    std::cout << "----------------------------------------\n";

                    for (size_t i = 0; i < processes.size(); ++i)
                    {
                        const auto& proc = processes[i];
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, proc.th32ProcessID);
                        if (hProcess)
                        {
                            FILETIME ftCreation, ftExit, ftKernel, ftUser;
                            IO_COUNTERS ioCounters;

                            if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser) &&
                                GetProcessIoCounters(hProcess, &ioCounters))
                            {
                                FILETIME prevKernelTime = prevKernelTimes[i];
                                FILETIME prevUserTime = prevUserTimes[i];
                                ULONGLONG currentTime = GetTickCount64();

                                double cpuUsage = CalculateCPUUsage(prevKernelTime, prevUserTime, ftKernel, ftUser, prevTime, currentTime);

                                if (!IsValidCPUUsage(cpuUsage))
                                {
                                    // Skip invalid CPU usage values
                                    prevKernelTimes[i] = ftKernel;
                                    prevUserTimes[i] = ftUser;
                                    continue;
                                }

                                PROCESS_MEMORY_COUNTERS pmc;
                                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
                                {
                                    DWORD_PTR ramUsage = pmc.WorkingSetSize / (1024 * 1024);
                                    std::wcout << std::left
                                        << std::setw(35) << proc.szExeFile
                                        << std::setw(10) << proc.th32ProcessID
                                        << std::fixed << std::setprecision(2)
                                        << std::setw(18) << cpuUsage
                                        << std::setw(10) << ramUsage
                                        << std::setw(15) << (ioCounters.ReadTransferCount / (1024 * 1024)) // MB
                                        << std::setw(15) << (ioCounters.WriteTransferCount / (1024 * 1024)) // MB
                                        << std::endl;

                                    // Log the information to file
                                    LogProcessInfo(proc.szExeFile, proc.th32ProcessID, cpuUsage, ramUsage,
                                        ioCounters.ReadTransferCount, ioCounters.WriteTransferCount);

                                    prevKernelTimes[i] = ftKernel;
                                    prevUserTimes[i] = ftUser;
                                }
                            }
                            CloseHandle(hProcess);
                        }
                    }
                    secondUpdate = false; // Only show the data on the second update

                    // Kullanıcıya geri dönme bilgisini göster
                    std::cout << "\nPress '0' to return to the menu.\n";
                }

                lastUpdate = now;
                prevTime = GetTickCount64();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
}

void ShowMenu()
{
    int choice;

    while (true)
    {
        std::cout << "\nSelect an option:\n";
        std::cout << "1. View System Processes\n";
        std::cout << "2. View User Processes\n";
        std::cout << "0. Exit\n";
        std::cout << "Enter choice (0, 1, or 2): ";
        std::cin >> choice;

        switch (choice)
        {
        case 1:
            ListProcesses(false, false);
            break;
        case 2:
            while (true)
            {
                int subChoice;
                std::cout << "\nSelect an option:\n";
                std::cout << "1. View Critical User Processes\n";
                std::cout << "2. View Standard User Processes\n";
                std::cout << "3. View Average Usage of a Specific Application\n"; // Yeni seçenek
                std::cout << "0. Back to Main Menu\n";
                std::cout << "Enter choice (0, 1, 2, or 3): ";
                std::cin >> subChoice;

                switch (subChoice)
                {
                case 1:
                    ListProcesses(true, true);
                    break;
                case 2:
                    ListProcesses(true, false);
                    break;
                case 3:
                {
                    std::wcin.ignore(); // ignore leftover newline character
                    std::wcout << L"Enter the name of the application (e.g., notepad.exe): ";
                    std::wstring appName;
                    std::getline(std::wcin, appName);
                    ShowAverageUsage(appName);
                    break;
                }
                case 0:
                    goto menu;
                default:
                    std::cerr << "Invalid choice. Please try again.\n";
                    break;
                }
            }
        case 0:
            std::cout << "Exiting...\n";
            return;
        default:
            std::cerr << "Invalid choice. Please try again.\n";
            break;
        }

    menu:
        continue;
    }
}


int main()
{
    ShowMenu();
    return 0;
}