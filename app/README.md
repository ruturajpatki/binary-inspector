# Binary Inspector — User Help Guide

Welcome to **Binary Inspector**, a clean, developer-friendly Windows desktop application designed to inspect the structural characteristics of Windows Portable Executables (PE) and Linux Executable and Linkable Format (ELF) binaries.

This guide helps you understand how to navigate and use the application to analyze your binary files.

---

## 1. Opening a Binary File

You can inspect any executable (`.exe`, `.dll`, `.sys`, `.so`, or extensionless binary) by loading it into the workspace:

- **Drag and Drop**: Simply drag a binary file from Windows File Explorer and drop it anywhere onto the application window.
- **Browse Dialog**: Click the **Browse Files** button in the empty startup screen, or click **Open File** in the top header bar, to choose a file via the Windows file browser.

Once a file is loaded, the application automatically inspects its binary signatures and structure. The file extension is ignored; the application reads actual magic headers to verify the format.

---

## 2. Navigating the Workspace

The workspace uses a split-screen design:

- **Navigation Sidebar (Left)**: Outlines the internal structures detected in the binary. Clicking on an item loads its specific metrics and data grids on the right.
- **Details Panel (Right)**: Displays properties, data tables, and headers corresponding to the selected sidebar category.
- **Resizable Splitter**: Click and drag the vertical border between the sidebar and the details panel to adjust their widths to your preference.
- **Close File**: Click the **Close (X)** button in the top right to close the active binary and return to the startup screen.

---

## 3. Viewing Binary Information

### File Overview

The default selection, **Overview**, provides a general summary:

- **File Metrics**: File size and formatted size.
- **Architecture**: Decoded target hardware architecture (such as `x86-64 (AMD64)`, `x86`, `ARM`, or `ARM64`).
- **Format & Type**: The layout classification (e.g., `PE32+`, `ELF64`) and file class (e.g., Windows GUI Executable, Linux Shared Object).
- **Execution Entry Point**: The memory address or offset where code execution begins.

### Headers Inspector

Analyze file headers to see compilation and subsystem settings:

- **For Windows Binaries (PE)**:
  - **DOS Header**: Legacy MZ header markers and PE header offset.
  - **NT Headers**: COFF Header properties (characteristics flags, section counts) and Optional Header details (subsystem targets, stack/heap reserve parameters, and the directories map).
- **For Linux Binaries (ELF)**:
  - **ELF Header**: Class specifications, target OS ABI, offsets of program/section headers, and string table indices.
  - **Program Headers**: Detailed segments listing segment types, memory alignments, and permissions (Read/Write/Execute flags).

### Sections Table

Displays all defined sections of the binary (e.g. `.text` for code, `.data` for variables, `.rsrc` for icons/resources).

- Each section displays its Virtual Address, Virtual Size, Raw Offset, Raw Size, and permissions (Readable, Writable, Executable).
- Use the **Search bar** at the top of the sections panel to quickly filter sections by name.

### Imports & Library Dependencies

Explore external files and functions that the binary depends on to run:

- **PE Binaries**: Lists imported DLLs (e.g. `KERNEL32.dll`). Expanding a DLL card displays the exact list of functions imported from that library.
- **ELF Binaries**: Lists required dynamic shared libraries (e.g. `libc.so.6`).
- A **live search filter** is available to find specific library names or imported function symbols.

### Exports & Symbols Table

Lists the exported functions (for libraries/DLLs) or the symbol table entries (for ELF binaries):

- Columns list the Symbol Name, Address, Size, Type (e.g. FUNC, OBJECT), and Binding scope (e.g. GLOBAL, LOCAL).
- Use the **Search bar** to filter list entries. This is highly optimized for large libraries with thousands of symbols.

---

## 4. Troubleshooting & Error States

If Binary Inspector is unable to analyze a file, it will display a clear error panel explaining the failure:

- **Unsupported Format**: The file does not have valid PE MZ or ELF signatures.
- **Corrupted / Truncated Binary**: The file header offsets point outside the file boundaries, or the file was cut off during copy/download.
- **Read Failures**: The file is locked by another process or lacks system read permissions.

To inspect a different file after an error, click the **Back** or **Try Another File** button to return to the startup drop zone.
