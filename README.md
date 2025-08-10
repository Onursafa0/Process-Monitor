# Windows Process Monitor

A simple console application for Windows that lists and monitors running processes, including system and user processes. It provides real-time CPU, RAM, and disk I/O usage statistics, and allows viewing average usage data of specific applications based on logged data.

---

## Features

- List **system processes** or **user processes**.
- Highlight **critical user processes** from a predefined list.
- Monitor and display real-time CPU, RAM (in MB), and Disk I/O (read/write in MB) usage for user processes.
- Log monitored process data to a text file (`process_log.txt`).
- Calculate and show average CPU and RAM usage of a specific application based on the log file.
- Interactive menu system with keyboard input to navigate.

---

## Requirements

- Windows OS
- C++17 or later compatible compiler (tested with MSVC)
- Windows SDK (for Windows API functions)

---

## Building

1. Make sure you have **Visual Studio** installed with the **Desktop development with C++** workload.
2. Clone or download the repository.
3. Open the project or compile the single `.cpp` file using MSVC:

```sh
cl /EHsc /std:c++17 /W4 process_monitor.cpp /link psapi.lib
```
- Alternatively, create a new Visual Studio Console Application project and add the source file.

- Ensure linking with `psapi.lib` (included in the project or via pragma comment in code).
---

## Usage
Run the executable from the command line. You will see a menu with options:

- 1: **View System Processes** (processes run by the system).

- 2: **View User Processes**.

   - From there, you can further filter to:

      - **Critical User Processes** (important Windows services and apps).

      - **Standard User Processes**.

      - **View average CPU and RAM usage of a specific application** by entering its executable name.

- 0: **Exit** the program.

When monitoring user processes, the program updates CPU, RAM, and disk I/O usage every 5 seconds. Press 0 during monitoring to return to the menu.

---

## Logging
- Monitored data is appended to `process_log.txt` in the executable directory.

- Log format per line:

```scss
ProcessName          PID       CPU%           RAM(MB)     DiskRead(MB)   DiskWrite(MB)
```
---

## Notes
- The program uses Windows API calls like `CreateToolhelp32Snapshot`, `GetProcessTimes`, and `GetProcessMemoryInfo`.

- Some processes may not provide all info due to permission restrictions.

- CPU usage is calculated between intervals and requires at least two sampling points.

- Critical processes are defined in the `criticalApplications` set within the source code.

