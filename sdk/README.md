# Binary Inspector SDK Developer Guide

**Binary Inspector SDK** is a lightweight, high-performance, programmatic PE (Portable Executable) and ELF (Executable and Linkable Format) binary inspection library written in pure Dart. It provides a clean, strongly typed, developer-friendly API for extracting binary characteristics, headers, sections, imports, and symbols without external native dependencies.

---

## Supported Formats

- **Portable Executable (PE)**: `.exe`, `.dll`, `.sys`, supporting PE32 (32-bit) and PE32+ (64-bit) for x86, x64, ARM, and ARM64.
- **Executable and Linkable Format (ELF)**: Executables, shared libraries (`.so`), object files, supporting ELF32 and ELF64 (little/big endian) for x86, x64, ARM, and AArch64.

---

## Installation & Setup

Add the SDK to your Dart or Flutter project's `pubspec.yaml`:

```yaml
dependencies:
  binary_inspector_sdk:
    path: path/to/sdk
```

Then, run `pub get` or `flutter pub get`.

---

## Basic Usage

### Import the SDK

```dart
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';
```

### Loading and Inspecting a Binary File

You can inspect a binary directly from its file path. The SDK automatically detects the binary format based on its magic headers (not the extension).

```dart
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';

void main() {
  try {
    final result = BinaryInspector.inspectFile('path/to/binary');

    // Access common binary information
    final overview = result.overview;
    print('Format: ${overview.format.displayName}');
    print('Architecture: ${overview.architecture.displayName}');
    print('Bitness: ${overview.bitness.displayName}');
    print('Entry Point: 0x${overview.entryPoint.toRadixString(16)}');

  } on BinaryParserException catch (e) {
    print('Parsing failed: ${e.message} (Type: ${e.type})');
  }
}
```

### Loading and Inspecting Raw Bytes

You can also parse a binary from a byte array (e.g., loaded from the network or drag-and-drop):

```dart
import 'dart:typed_data';
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';

void parseBytes(Uint8List bytes) {
  final result = BinaryInspector.inspectBytes(bytes, 'my_file.bin');
  print('Parsed file size: ${result.overview.fileSize}');
}
```

---

## Common Abstraction Model

Every parse returns a `BinaryResult` object which exposes a unified abstraction of the binary:

1. **`overview`**: General file data (format, size, bitness, endianness, entry point).
2. **`sections`**: List of sections (`BinarySection`) with name, address, size, and read/write/execute permissions.
3. **`dependencies`**: Dynamic library dependencies or imports.
4. **`symbols`**: Exported functions (PE) or symbols table entries (ELF).

```dart
// Iterate over common sections
for (final sec in result.sections) {
  print('Section ${sec.name}: Address 0x${sec.virtualAddress.toRadixString(16)}, R:${sec.readable} W:${sec.writable} X:${sec.executable}');
}

// Access dependencies
for (final dep in result.dependencies) {
  print('Depends on: ${dep.name}');
}
```

---

## Format-Specific Inspections

If you require details specific to a format, you can access the underlying models if they are non-null:

### Portable Executable (PE) Details

```dart
if (result.overview.format == BinaryFormat.pe) {
  final pe = result.peData!;

  // Access DOS Header
  print('MZ Magic: 0x${pe.dosHeader.magic.toRadixString(16)}');
  print('PE Offset: ${pe.dosHeader.peHeaderOffset}');

  // Access NT/COFF Headers
  print('Characteristics: ${pe.ntHeaders.coffHeader.characteristicsList}');

  // Access Optional Header & Data Directories
  print('Subsystem: ${pe.ntHeaders.optionalHeader.subsystemName}');
  for (final dir in pe.ntHeaders.optionalHeader.dataDirectories) {
    print('Dir: ${dir.name} at RVA: 0x${dir.virtualAddress.toRadixString(16)}');
  }
}
```

### Executable and Linkable Format (ELF) Details

```dart
if (result.overview.format == BinaryFormat.elf) {
  final elf = result.elfData!;

  // Access ELF Header
  print('ELF Class: ${elf.header.className}');
  print('OS ABI: ${elf.header.osAbiName}');
  print('Program Header Count: ${elf.header.phNum}');

  // Access Program Headers / Segments
  for (final ph in elf.programHeaders) {
    print('Segment type: ${ph.typeName}, Offset: 0x${ph.offset.toRadixString(16)}');
  }
}
```

---

## Error Handling

All parsing errors throw a `BinaryParserException`. You should catch this exception to handle failures gracefully.

The exception contains a `type` property indicating the failure category:

- `unknown_format`: The file is neither a valid PE nor a valid ELF binary.
- `invalid_binary`: The binary structure is corrupted (e.g. invalid offset pointers).
- `truncated`: The input bytes were cut off before headers could be fully parsed.
- `unsupported`: The binary uses a format subclass or architecture version not supported by the initial release.
- `io_error`: The library could not read the file from disk due to permission or system issues.
