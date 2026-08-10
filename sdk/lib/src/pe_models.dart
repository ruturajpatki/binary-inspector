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

class PeModel {
  final PeDosHeader dosHeader;
  final PeNtHeaders ntHeaders;
  final List<PeSection> sections;
  final List<PeImportDirectory> imports;
  final List<PeExport> exports;

  const PeModel({
    required this.dosHeader,
    required this.ntHeaders,
    required this.sections,
    required this.imports,
    required this.exports,
  });
}

class PeDosHeader {
  final int magic;              // e_magic (should be 0x5A4D, 'MZ')
  final int usedHeaderSize;     // based on e_lfanew or direct offsets
  final int relocationOffset;   // e_lfarlc
  final int peHeaderOffset;     // e_lfanew (pointer to NT headers)

  const PeDosHeader({
    required this.magic,
    required this.usedHeaderSize,
    required this.relocationOffset,
    required this.peHeaderOffset,
  });
}

class PeNtHeaders {
  final int signature;          // 'PE\0\0' (0x00004550)
  final PeCoffHeader coffHeader;
  final PeOptionalHeader optionalHeader;

  const PeNtHeaders({
    required this.signature,
    required this.coffHeader,
    required this.optionalHeader,
  });
}

class PeCoffHeader {
  final int machine;
  final int numberOfSections;
  final int timeDateStamp;
  final int pointerToSymbolTable;
  final int numberOfSymbols;
  final int sizeOfOptionalHeader;
  final int characteristics;

  const PeCoffHeader({
    required this.machine,
    required this.numberOfSections,
    required this.timeDateStamp,
    required this.pointerToSymbolTable,
    required this.numberOfSymbols,
    required this.sizeOfOptionalHeader,
    required this.characteristics,
  });

  String get machineName {
    switch (machine) {
      case 0x014c: return 'Intel 386 (x86)';
      case 0x8664: return 'AMD64 (x86-64)';
      case 0x01c0: return 'ARM Little Endian';
      case 0xaa64: return 'ARM64';
      case 0x0200: return 'Intel Itanium (IA-64)';
      default: return 'Unknown (0x${machine.toRadixString(16)})';
    }
  }

  List<String> get characteristicsList {
    final list = <String>[];
    if (characteristics & 0x0001 != 0) list.add('RELOCS_STRIPPED');
    if (characteristics & 0x0002 != 0) list.add('EXECUTABLE_IMAGE');
    if (characteristics & 0x0004 != 0) list.add('LINE_NUMS_STRIPPED');
    if (characteristics & 0x0008 != 0) list.add('LOCAL_SYMS_STRIPPED');
    if (characteristics & 0x0010 != 0) list.add('AGGRESSIVE_WS_TRIM');
    if (characteristics & 0x0020 != 0) list.add('LARGE_ADDRESS_AWARE');
    if (characteristics & 0x0080 != 0) list.add('BYTES_REVERSED_LO');
    if (characteristics & 0x0100 != 0) list.add('32BIT_MACHINE');
    if (characteristics & 0x0200 != 0) list.add('DEBUG_STRIPPED');
    if (characteristics & 0x0400 != 0) list.add('REMOVABLE_RUN_FROM_SWAP');
    if (characteristics & 0x0800 != 0) list.add('NET_RUN_FROM_SWAP');
    if (characteristics & 0x1000 != 0) list.add('SYSTEM');
    if (characteristics & 0x2000 != 0) list.add('DLL');
    if (characteristics & 0x4000 != 0) list.add('UP_SYSTEM_ONLY');
    if (characteristics & 0x8000 != 0) list.add('BYTES_REVERSED_HI');
    return list;
  }
}

class PeOptionalHeader {
  final int magic;              // 0x10b (PE32) or 0x20b (PE32+)
  final int majorLinkerVersion;
  final int minorLinkerVersion;
  final int sizeOfCode;
  final int sizeOfInitializedData;
  final int sizeOfUninitializedData;
  final int addressOfEntryPoint;
  final int baseOfCode;
  final int? baseOfData;        // Only present in PE32 (not PE32+)
  final int imageBase;          // 32-bit or 64-bit value
  final int sectionAlignment;
  final int fileAlignment;
  final int majorOperatingSystemVersion;
  final int minorOperatingSystemVersion;
  final int majorImageVersion;
  final int minorImageVersion;
  final int majorSubsystemVersion;
  final int minorSubsystemVersion;
  final int win32VersionValue;
  final int sizeOfImage;
  final int sizeOfHeaders;
  final int checkSum;
  final int subsystem;
  final int dllCharacteristics;
  final int sizeOfStackReserve;
  final int sizeOfStackCommit;
  final int sizeOfHeapReserve;
  final int sizeOfHeapCommit;
  final int loaderFlags;
  final int numberOfRvaAndSizes;
  final List<PeDataDirectory> dataDirectories;

  const PeOptionalHeader({
    required this.magic,
    required this.majorLinkerVersion,
    required this.minorLinkerVersion,
    required this.sizeOfCode,
    required this.sizeOfInitializedData,
    required this.sizeOfUninitializedData,
    required this.addressOfEntryPoint,
    required this.baseOfCode,
    this.baseOfData,
    required this.imageBase,
    required this.sectionAlignment,
    required this.fileAlignment,
    required this.majorOperatingSystemVersion,
    required this.minorOperatingSystemVersion,
    required this.majorImageVersion,
    required this.minorImageVersion,
    required this.majorSubsystemVersion,
    required this.minorSubsystemVersion,
    required this.win32VersionValue,
    required this.sizeOfImage,
    required this.sizeOfHeaders,
    required this.checkSum,
    required this.subsystem,
    required this.dllCharacteristics,
    required this.sizeOfStackReserve,
    required this.sizeOfStackCommit,
    required this.sizeOfHeapReserve,
    required this.sizeOfHeapCommit,
    required this.loaderFlags,
    required this.numberOfRvaAndSizes,
    required this.dataDirectories,
  });

  bool get isPE32Plus => magic == 0x20b;

  String get subsystemName {
    switch (subsystem) {
      case 0: return 'UNKNOWN';
      case 1: return 'NATIVE';
      case 2: return 'WINDOWS_GUI';
      case 3: return 'WINDOWS_CUI';
      case 5: return 'OS2_CUI';
      case 7: return 'POSIX_CUI';
      case 8: return 'NATIVE_WINDOWS';
      case 9: return 'WINDOWS_CE_GUI';
      case 10: return 'EFI_APPLICATION';
      case 11: return 'EFI_BOOT_SERVICE_DRIVER';
      case 12: return 'EFI_RUNTIME_DRIVER';
      case 13: return 'EFI_ROM';
      case 14: return 'XBOX';
      case 16: return 'WINDOWS_BOOT_APPLICATION';
      default: return 'Unknown ($subsystem)';
    }
  }

  List<String> get dllCharacteristicsList {
    final list = <String>[];
    if (dllCharacteristics & 0x0020 != 0) list.add('HIGH_ENTROPY_VA');
    if (dllCharacteristics & 0x0040 != 0) list.add('DYNAMIC_BASE');
    if (dllCharacteristics & 0x0080 != 0) list.add('FORCE_INTEGRITY');
    if (dllCharacteristics & 0x0100 != 0) list.add('NX_COMPAT');
    if (dllCharacteristics & 0x0200 != 0) list.add('NO_ISOLATION');
    if (dllCharacteristics & 0x0400 != 0) list.add('NO_SEH');
    if (dllCharacteristics & 0x0800 != 0) list.add('NO_BIND');
    if (dllCharacteristics & 0x1000 != 0) list.add('APPCONTAINER');
    if (dllCharacteristics & 0x2000 != 0) list.add('WDM_DRIVER');
    if (dllCharacteristics & 0x4000 != 0) list.add('GUARD_CF');
    if (dllCharacteristics & 0x8000 != 0) list.add('TERMINAL_SERVER_AWARE');
    return list;
  }
}

class PeDataDirectory {
  final String name;
  final int virtualAddress;
  final int size;

  const PeDataDirectory({
    required this.name,
    required this.virtualAddress,
    required this.size,
  });
}

class PeSection {
  final String name;
  final int virtualSize;
  final int virtualAddress;
  final int rawDataSize;
  final int rawDataOffset;
  final int pointerToRelocations;
  final int pointerToLinenumbers;
  final int numberOfRelocations;
  final int numberOfLinenumbers;
  final int characteristics;

  const PeSection({
    required this.name,
    required this.virtualSize,
    required this.virtualAddress,
    required this.rawDataSize,
    required this.rawDataOffset,
    required this.pointerToRelocations,
    required this.pointerToLinenumbers,
    required this.numberOfRelocations,
    required this.numberOfLinenumbers,
    required this.characteristics,
  });

  bool get isReadable => characteristics & 0x40000000 != 0;
  bool get isWritable => characteristics & 0x80000000 != 0;
  bool get isExecutable => characteristics & 0x20000000 != 0;

  List<String> get characteristicsList {
    final list = <String>[];
    if (characteristics & 0x00000020 != 0) list.add('CNT_CODE');
    if (characteristics & 0x00000040 != 0) list.add('CNT_INITIALIZED_DATA');
    if (characteristics & 0x00000080 != 0) list.add('CNT_UNINITIALIZED_DATA');
    if (characteristics & 0x02000000 != 0) list.add('MEM_DISCARDABLE');
    if (characteristics & 0x04000000 != 0) list.add('MEM_NOT_CACHED');
    if (characteristics & 0x08000000 != 0) list.add('MEM_NOT_PAGED');
    if (characteristics & 0x10000000 != 0) list.add('MEM_SHARED');
    if (characteristics & 0x20000000 != 0) list.add('MEM_EXECUTE');
    if (characteristics & 0x40000000 != 0) list.add('MEM_READ');
    if (characteristics & 0x80000000 != 0) list.add('MEM_WRITE');
    return list;
  }
}

class PeImportDirectory {
  final String dllName;
  final int importLookupTableRva;
  final int timeDateStamp;
  final int forwarderChain;
  final int nameRva;
  final int importAddressTableRva;
  final List<PeImportFunction> functions;

  const PeImportDirectory({
    required this.dllName,
    required this.importLookupTableRva,
    required this.timeDateStamp,
    required this.forwarderChain,
    required this.nameRva,
    required this.importAddressTableRva,
    required this.functions,
  });
}

class PeImportFunction {
  final String name;
  final int hint;
  final int ordinal;
  final bool isByOrdinal;

  const PeImportFunction({
    required this.name,
    required this.hint,
    required this.ordinal,
    required this.isByOrdinal,
  });
}

class PeExport {
  final String name;
  final int ordinal;
  final int rva;
  final String? forwarder;

  const PeExport({
    required this.name,
    required this.ordinal,
    required this.rva,
    this.forwarder,
  });
}
