# Binary Inspector

A lightweight, developer-friendly **PE and ELF binary inspection toolkit** written in pure Dart.

Binary Inspector consists of two parts:

- **Binary Inspector SDK** — a reusable Dart package for programmatic PE and ELF inspection.
- **Binary Inspector** — a Windows desktop reference application built on top of the SDK.

The SDK lets developers inspect executable structure without implementing PE/ELF parsing themselves, while the desktop application provides a convenient visual way to explore binaries.

---

[screenshot here]

---

## Why Binary Inspector?

Sometimes you don't need a disassembler, debugger, or full reverse-engineering suite.

You simply want to answer questions like:

- What kind of binary is this?
- Is it 32-bit or 64-bit?
- Which CPU architecture was it built for?
- What sections does it contain?
- What libraries does it depend on?
- What functions does it import or export?
- What does its executable header contain?
- Is this actually a valid PE or ELF binary?

Binary Inspector is designed for exactly that space:

> **Understand what's inside a binary without opening a full reverse-engineering suite.**

---

## ✨ Features

### PE Support

Inspect Windows Portable Executable files including:

- `.exe`
- `.dll`
- `.sys`

Supports:

- PE32
- PE32+
- x86
- x86-64 / AMD64
- ARM
- ARM64

Explore:

- DOS Header
- NT / COFF Headers
- Optional Header
- Data Directories
- Sections
- Imported DLLs and functions
- Exported functions
- Architecture and bitness
- Subsystem
- Entry point
- Image base
- DLL characteristics

### ELF Support

Inspect Executable and Linkable Format binaries including:

- Executables
- Shared libraries (`.so`)
- Object files
- Extensionless binaries

Supports:

- ELF32
- ELF64
- Little-endian
- Big-endian
- x86
- x86-64
- ARM
- AArch64

Explore:

- ELF Header
- Program Headers
- Sections
- Dynamic dependencies
- Symbols
- Architecture
- Entry point
- File type
- OS ABI

---

## 🧩 Binary Inspector SDK

The **Binary Inspector SDK** is the core of this project.

It provides a strongly typed API for programmatically inspecting PE and ELF binaries from Dart or Flutter applications.

```dart
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';

void main() {
  final result = BinaryInspector.inspectFile('sample.exe');

  print('Format: ${result.overview.format.displayName}');
  print('Architecture: ${result.overview.architecture.displayName}');
  print('Bitness: ${result.overview.bitness.displayName}');
  print(
    'Entry Point: '
    '0x${result.overview.entryPoint.toRadixString(16)}',
  );
}
