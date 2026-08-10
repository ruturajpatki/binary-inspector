/*
 * Package: Flutter-BinaryInspectorSDK
 * Author: Ruturaj V Patki
 * Email: ruturajvpatki@zohomail.com
 *
 * Copyright 2026 Ruturaj V Patki
 * Originally authored by Ruturaj V Patki.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'pe_models.dart';
import 'elf_models.dart';

enum BinaryFormat {
  pe,
  elf,
  unknown;

  String get displayName {
    switch (this) {
      case BinaryFormat.pe: return 'PE (Portable Executable)';
      case BinaryFormat.elf: return 'ELF (Executable and Linkable Format)';
      case BinaryFormat.unknown: return 'Unknown Format';
    }
  }
}

enum BinaryArchitecture {
  x86,
  x64,
  arm,
  arm64,
  unknown;

  String get displayName {
    switch (this) {
      case BinaryArchitecture.x86: return 'x86';
      case BinaryArchitecture.x64: return 'x86-64 (AMD64)';
      case BinaryArchitecture.arm: return 'ARM';
      case BinaryArchitecture.arm64: return 'ARM64';
      case BinaryArchitecture.unknown: return 'Unknown';
    }
  }
}

enum BinaryBitness {
  b32,
  b64,
  unknown;

  String get displayName {
    switch (this) {
      case BinaryBitness.b32: return '32-bit';
      case BinaryBitness.b64: return '64-bit';
      case BinaryBitness.unknown: return 'Unknown';
    }
  }
}

enum BinaryEndianness {
  little,
  big,
  unknown;

  String get displayName {
    switch (this) {
      case BinaryEndianness.little: return 'Little Endian';
      case BinaryEndianness.big: return 'Big Endian';
      case BinaryEndianness.unknown: return 'Unknown';
    }
  }
}

enum BinaryFileType {
  executable,
  sharedLibrary,
  objectFile,
  unknown;

  String get displayName {
    switch (this) {
      case BinaryFileType.executable: return 'Executable';
      case BinaryFileType.sharedLibrary: return 'Shared Library / DLL';
      case BinaryFileType.objectFile: return 'Object File';
      case BinaryFileType.unknown: return 'Unknown Type';
    }
  }
}

class BinaryOverview {
  final String fileName;
  final int fileSize;
  final BinaryFormat format;
  final BinaryArchitecture architecture;
  final BinaryBitness bitness;
  final BinaryEndianness endianness;
  final BinaryFileType fileType;
  final int entryPoint;
  final String formatIdentifier; // e.g. "PE32+", "ELF64"

  const BinaryOverview({
    required this.fileName,
    required this.fileSize,
    required this.format,
    required this.architecture,
    required this.bitness,
    required this.endianness,
    required this.fileType,
    required this.entryPoint,
    required this.formatIdentifier,
  });
}

class BinarySection {
  final String name;
  final int virtualAddress;
  final int virtualSize;
  final int rawDataOffset;
  final int rawDataSize;
  final bool readable;
  final bool writable;
  final bool executable;
  final Map<String, dynamic> customProperties;

  const BinarySection({
    required this.name,
    required this.virtualAddress,
    required this.virtualSize,
    required this.rawDataOffset,
    required this.rawDataSize,
    required this.readable,
    required this.writable,
    required this.executable,
    this.customProperties = const {},
  });
}

class BinaryDependency {
  final String name;
  final List<String> importedSymbols;

  const BinaryDependency({
    required this.name,
    required this.importedSymbols,
  });
}

class BinarySymbol {
  final String name;
  final int address;
  final int size;
  final String type; // e.g. "FUNC", "OBJECT", "Export"
  final String binding; // e.g. "GLOBAL", "LOCAL", "WEAK"

  const BinarySymbol({
    required this.name,
    required this.address,
    required this.size,
    required this.type,
    required this.binding,
  });
}

class BinaryResult {
  final BinaryOverview overview;
  final List<BinarySection> sections;
  final List<BinaryDependency> dependencies;
  final List<BinarySymbol> symbols;
  
  // Format-specific models (only one will be non-null based on format)
  final PeModel? peData;
  final ElfModel? elfData;

  const BinaryResult({
    required this.overview,
    required this.sections,
    required this.dependencies,
    required this.symbols,
    this.peData,
    this.elfData,
  });
}

class BinaryParserException implements Exception {
  final String message;
  final String type; // 'unknown_format', 'invalid_binary', 'truncated', 'unsupported', 'io_error'

  const BinaryParserException(this.message, this.type);

  @override
  String toString() => 'BinaryParserException[$type]: $message';
}
