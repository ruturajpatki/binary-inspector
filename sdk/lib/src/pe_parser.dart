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

import 'dart:typed_data';
import 'binary_models.dart';
import 'binary_reader.dart';
import 'pe_models.dart';

class PeParser {
  static bool detect(Uint8List bytes) {
    if (bytes.length < 64) return false;
    // DOS magic must be MZ
    if (bytes[0] != 0x4D || bytes[1] != 0x5A) return false;
    
    // Read e_lfanew
    final data = ByteData.sublistView(bytes);
    final peOffset = data.getUint32(60, Endian.little);
    if (peOffset < 0 || peOffset + 4 > bytes.length) return false;
    
    // PE signature must be PE\0\0
    return bytes[peOffset] == 0x50 &&
           bytes[peOffset + 1] == 0x45 &&
           bytes[peOffset + 2] == 0 &&
           bytes[peOffset + 3] == 0;
  }

  static BinaryResult parse(Uint8List bytes, String fileName) {
    final reader = BinaryReader(bytes, defaultEndian: Endian.little);

    if (bytes.length < 64) {
      throw const BinaryParserException('File size is too small to be a PE binary.', 'truncated');
    }

    final dosMagic = reader.readUint16(0);
    if (dosMagic != 0x5A4D) {
      throw const BinaryParserException('Invalid DOS MZ magic header.', 'invalid_binary');
    }

    final peHeaderOffset = reader.readUint32(60);
    if (peHeaderOffset + 4 > bytes.length) {
      throw const BinaryParserException('Invalid PE header offset.', 'truncated');
    }

    final peSignature = reader.readUint32(peHeaderOffset);
    if (peSignature != 0x00004550) {
      throw const BinaryParserException('Invalid PE signature.', 'invalid_binary');
    }

    // Parse COFF Header
    final coffOffset = peHeaderOffset + 4;
    final machine = reader.readUint16(coffOffset);
    final numberOfSections = reader.readUint16(coffOffset + 2);
    final timeDateStamp = reader.readUint32(coffOffset + 4);
    final pointerToSymbolTable = reader.readUint32(coffOffset + 8);
    final numberOfSymbols = reader.readUint32(coffOffset + 12);
    final sizeOfOptionalHeader = reader.readUint16(coffOffset + 16);
    final characteristics = reader.readUint16(coffOffset + 18);

    final coffHeader = PeCoffHeader(
      machine: machine,
      numberOfSections: numberOfSections,
      timeDateStamp: timeDateStamp,
      pointerToSymbolTable: pointerToSymbolTable,
      numberOfSymbols: numberOfSymbols,
      sizeOfOptionalHeader: sizeOfOptionalHeader,
      characteristics: characteristics,
    );

    // Parse Optional Header
    final optionalOffset = coffOffset + 20;
    if (optionalOffset + sizeOfOptionalHeader > bytes.length) {
      throw const BinaryParserException('Optional header exceeds file size.', 'truncated');
    }

    final magic = reader.readUint16(optionalOffset);
    final isPE32Plus = magic == 0x20b;
    if (magic != 0x10b && magic != 0x20b) {
      throw BinaryParserException('Unsupported or invalid optional header magic: 0x${magic.toRadixString(16)}', 'unsupported');
    }

    final majorLinkerVersion = reader.readUint8(optionalOffset + 2);
    final minorLinkerVersion = reader.readUint8(optionalOffset + 3);
    final sizeOfCode = reader.readUint32(optionalOffset + 4);
    final sizeOfInitializedData = reader.readUint32(optionalOffset + 8);
    final sizeOfUninitializedData = reader.readUint32(optionalOffset + 12);
    final addressOfEntryPoint = reader.readUint32(optionalOffset + 16);
    final baseOfCode = reader.readUint32(optionalOffset + 20);

    int? baseOfData;
    int imageBase;
    int sectionAlignment;
    int fileAlignment;
    int majorOperatingSystemVersion;
    int minorOperatingSystemVersion;
    int majorImageVersion;
    int minorImageVersion;
    int majorSubsystemVersion;
    int minorSubsystemVersion;
    int win32VersionValue;
    final int sizeOfImage = reader.readUint32(optionalOffset + 56);
    final int sizeOfHeaders = reader.readUint32(optionalOffset + 60);
    final int checkSum = reader.readUint32(optionalOffset + 64);
    final int subsystem = reader.readUint16(optionalOffset + 68);
    final int dllCharacteristics = reader.readUint16(optionalOffset + 70);
    int sizeOfStackReserve;
    int sizeOfStackCommit;
    int sizeOfHeapReserve;
    int sizeOfHeapCommit;
    int loaderFlags;
    int numberOfRvaAndSizes;
    int dataDirectoriesOffset;

    if (!isPE32Plus) {
      // PE32 (32-bit)
      baseOfData = reader.readUint32(optionalOffset + 24);
      imageBase = reader.readUint32(optionalOffset + 28);
      sectionAlignment = reader.readUint32(optionalOffset + 32);
      fileAlignment = reader.readUint32(optionalOffset + 36);
      majorOperatingSystemVersion = reader.readUint16(optionalOffset + 40);
      minorOperatingSystemVersion = reader.readUint16(optionalOffset + 42);
      majorImageVersion = reader.readUint16(optionalOffset + 44);
      minorImageVersion = reader.readUint16(optionalOffset + 46);
      majorSubsystemVersion = reader.readUint16(optionalOffset + 48);
      minorSubsystemVersion = reader.readUint16(optionalOffset + 50);
      win32VersionValue = reader.readUint32(optionalOffset + 52);
      sizeOfStackReserve = reader.readUint32(optionalOffset + 72);
      sizeOfStackCommit = reader.readUint32(optionalOffset + 76);
      sizeOfHeapReserve = reader.readUint32(optionalOffset + 80);
      sizeOfHeapCommit = reader.readUint32(optionalOffset + 84);
      loaderFlags = reader.readUint32(optionalOffset + 88);
      numberOfRvaAndSizes = reader.readUint32(optionalOffset + 92);
      dataDirectoriesOffset = optionalOffset + 96;
    } else {
      // PE32+ (64-bit)
      imageBase = reader.readUint64(optionalOffset + 24);
      sectionAlignment = reader.readUint32(optionalOffset + 32);
      fileAlignment = reader.readUint32(optionalOffset + 36);
      majorOperatingSystemVersion = reader.readUint16(optionalOffset + 40);
      minorOperatingSystemVersion = reader.readUint16(optionalOffset + 42);
      majorImageVersion = reader.readUint16(optionalOffset + 44);
      minorImageVersion = reader.readUint16(optionalOffset + 46);
      majorSubsystemVersion = reader.readUint16(optionalOffset + 48);
      minorSubsystemVersion = reader.readUint16(optionalOffset + 50);
      win32VersionValue = reader.readUint32(optionalOffset + 52);
      sizeOfStackReserve = reader.readUint64(optionalOffset + 72);
      sizeOfStackCommit = reader.readUint64(optionalOffset + 80);
      sizeOfHeapReserve = reader.readUint64(optionalOffset + 88);
      sizeOfHeapCommit = reader.readUint64(optionalOffset + 96);
      loaderFlags = reader.readUint32(optionalOffset + 104);
      numberOfRvaAndSizes = reader.readUint32(optionalOffset + 108);
      dataDirectoriesOffset = optionalOffset + 112;
    }

    // Parse Data Directories
    final directoriesList = <PeDataDirectory>[];
    final dirNames = [
      'EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY', 'BASERELOC',
      'DEBUG', 'ARCHITECTURE', 'GLOBALPTR', 'TLS', 'LOAD_CONFIG', 'BOUND_IMPORT',
      'IAT', 'DELAY_IMPORT', 'COM_DESCRIPTOR', 'RESERVED'
    ];

    for (var i = 0; i < numberOfRvaAndSizes; i++) {
      if (i >= 16) break; // Maximum 16 standard data directories
      final dirOffset = dataDirectoriesOffset + (i * 8);
      if (dirOffset + 8 > bytes.length) break;
      final va = reader.readUint32(dirOffset);
      final size = reader.readUint32(dirOffset + 4);
      directoriesList.add(PeDataDirectory(
        name: dirNames[i],
        virtualAddress: va,
        size: size,
      ));
    }

    final optionalHeader = PeOptionalHeader(
      magic: magic,
      majorLinkerVersion: majorLinkerVersion,
      minorLinkerVersion: minorLinkerVersion,
      sizeOfCode: sizeOfCode,
      sizeOfInitializedData: sizeOfInitializedData,
      sizeOfUninitializedData: sizeOfUninitializedData,
      addressOfEntryPoint: addressOfEntryPoint,
      baseOfCode: baseOfCode,
      baseOfData: baseOfData,
      imageBase: imageBase,
      sectionAlignment: sectionAlignment,
      fileAlignment: fileAlignment,
      majorOperatingSystemVersion: majorOperatingSystemVersion,
      minorOperatingSystemVersion: minorOperatingSystemVersion,
      majorImageVersion: majorImageVersion,
      minorImageVersion: minorImageVersion,
      majorSubsystemVersion: majorSubsystemVersion,
      minorSubsystemVersion: minorSubsystemVersion,
      win32VersionValue: win32VersionValue,
      sizeOfImage: sizeOfImage,
      sizeOfHeaders: sizeOfHeaders,
      checkSum: checkSum,
      subsystem: subsystem,
      dllCharacteristics: dllCharacteristics,
      sizeOfStackReserve: sizeOfStackReserve,
      sizeOfStackCommit: sizeOfStackCommit,
      sizeOfHeapReserve: sizeOfHeapReserve,
      sizeOfHeapCommit: sizeOfHeapCommit,
      loaderFlags: loaderFlags,
      numberOfRvaAndSizes: numberOfRvaAndSizes,
      dataDirectories: directoriesList,
    );

    // Parse Sections
    final sectionsOffset = optionalOffset + sizeOfOptionalHeader;
    final sectionsList = <PeSection>[];

    for (var i = 0; i < numberOfSections; i++) {
      final secOffset = sectionsOffset + (i * 40);
      if (secOffset + 40 > bytes.length) {
        // Sections table is truncated
        break;
      }
      final name = reader.readString(secOffset, 8);
      final virtualSize = reader.readUint32(secOffset + 8);
      final virtualAddress = reader.readUint32(secOffset + 12);
      final rawDataSize = reader.readUint32(secOffset + 16);
      final rawDataOffset = reader.readUint32(secOffset + 20);
      final pointerToRelocations = reader.readUint32(secOffset + 24);
      final pointerToLinenumbers = reader.readUint32(secOffset + 28);
      final numberOfRelocations = reader.readUint16(secOffset + 32);
      final numberOfLinenumbers = reader.readUint16(secOffset + 34);
      final characteristics = reader.readUint32(secOffset + 36);

      sectionsList.add(PeSection(
        name: name,
        virtualSize: virtualSize,
        virtualAddress: virtualAddress,
        rawDataSize: rawDataSize,
        rawDataOffset: rawDataOffset,
        pointerToRelocations: pointerToRelocations,
        pointerToLinenumbers: pointerToLinenumbers,
        numberOfRelocations: numberOfRelocations,
        numberOfLinenumbers: numberOfLinenumbers,
        characteristics: characteristics,
      ));
    }

    int rvaToOffset(int rva) {
      if (rva == 0) return 0;
      for (final section in sectionsList) {
        if (rva >= section.virtualAddress &&
            rva < section.virtualAddress + section.virtualSize) {
          final diff = rva - section.virtualAddress;
          if (diff < section.rawDataSize) {
            return section.rawDataOffset + diff;
          }
        }
      }
      return 0;
    }

    // Parse Imports
    final importsList = <PeImportDirectory>[];
    if (directoriesList.length > 1) {
      final importDir = directoriesList[1];
      if (importDir.virtualAddress != 0 && importDir.size != 0) {
        var importOffset = rvaToOffset(importDir.virtualAddress);
        if (importOffset != 0) {
          while (importOffset + 20 <= bytes.length) {
            final iltRva = reader.readUint32(importOffset);
            final timeDate = reader.readUint32(importOffset + 4);
            final forwarder = reader.readUint32(importOffset + 8);
            final nameRva = reader.readUint32(importOffset + 12);
            final iatRva = reader.readUint32(importOffset + 16);

            // Null entry terminates
            if (iltRva == 0 && nameRva == 0 && iatRva == 0) {
              break;
            }

            final nameOffset = rvaToOffset(nameRva);
            String dllName = 'Unknown';
            if (nameOffset != 0) {
              try {
                dllName = reader.readNullTerminatedString(nameOffset);
              } catch (_) {}
            }

            // Fallback: ILT or IAT
            final lookupTableRva = iltRva != 0 ? iltRva : iatRva;
            var lookupOffset = rvaToOffset(lookupTableRva);
            final functions = <PeImportFunction>[];

            if (lookupOffset != 0) {
              final step = isPE32Plus ? 8 : 4;
              while (lookupOffset + step <= bytes.length) {
                final entry = isPE32Plus 
                    ? reader.readUint64(lookupOffset) 
                    : reader.readUint32(lookupOffset);
                if (entry == 0) break;

                final isByOrdinal = isPE32Plus 
                    ? (entry & (1 << 63)) != 0 
                    : (entry & (1 << 31)) != 0;

                if (isByOrdinal) {
                  final ordinal = entry & 0xFFFF;
                  functions.add(PeImportFunction(
                    name: 'Ordinal_$ordinal',
                    hint: 0,
                    ordinal: ordinal,
                    isByOrdinal: true,
                  ));
                } else {
                  final nameValRva = entry & 0x7FFFFFFF;
                  final funcNameOffset = rvaToOffset(nameValRva);
                  if (funcNameOffset != 0 && funcNameOffset + 2 <= bytes.length) {
                    try {
                      final hint = reader.readUint16(funcNameOffset);
                      final funcName = reader.readNullTerminatedString(funcNameOffset + 2);
                      functions.add(PeImportFunction(
                        name: funcName,
                        hint: hint,
                        ordinal: 0,
                        isByOrdinal: false,
                      ));
                    } catch (_) {}
                  }
                }
                lookupOffset += step;
              }
            }

            importsList.add(PeImportDirectory(
              dllName: dllName,
              importLookupTableRva: iltRva,
              timeDateStamp: timeDate,
              forwarderChain: forwarder,
              nameRva: nameRva,
              importAddressTableRva: iatRva,
              functions: functions,
            ));

            importOffset += 20;
          }
        }
      }
    }

    // Parse Exports
    final exportsList = <PeExport>[];
    if (directoriesList.isNotEmpty) {
      final exportDir = directoriesList[0];
      if (exportDir.virtualAddress != 0 && exportDir.size != 0) {
        final exportOffset = rvaToOffset(exportDir.virtualAddress);
        if (exportOffset != 0 && exportOffset + 40 <= bytes.length) {
          final base = reader.readUint32(exportOffset + 16);
          final numNames = reader.readUint32(exportOffset + 24);
          final eatRva = reader.readUint32(exportOffset + 28);
          final enptRva = reader.readUint32(exportOffset + 32);
          final eotRva = reader.readUint32(exportOffset + 36);

          final eatOffset = rvaToOffset(eatRva);
          final enptOffset = rvaToOffset(enptRva);
          final eotOffset = rvaToOffset(eotRva);

          if (eatOffset != 0 && enptOffset != 0 && eotOffset != 0) {
            for (var i = 0; i < numNames; i++) {
              final namePtrOffset = enptOffset + (i * 4);
              if (namePtrOffset + 4 > bytes.length) break;
              final nameRva = reader.readUint32(namePtrOffset);
              final nameValOffset = rvaToOffset(nameRva);
              if (nameValOffset == 0) continue;

              String expName = 'Unknown';
              try {
                expName = reader.readNullTerminatedString(nameValOffset);
              } catch (_) {}

              final ordIndexOffset = eotOffset + (i * 2);
              if (ordIndexOffset + 2 > bytes.length) break;
              final ordIndex = reader.readUint16(ordIndexOffset);

              final funcPtrOffset = eatOffset + (ordIndex * 4);
              if (funcPtrOffset + 4 > bytes.length) break;
              final funcRva = reader.readUint32(funcPtrOffset);

              // Check if forwarder RVA
              String? forwarderStr;
              if (funcRva >= exportDir.virtualAddress &&
                  funcRva < exportDir.virtualAddress + exportDir.size) {
                final forwardOffset = rvaToOffset(funcRva);
                if (forwardOffset != 0) {
                  try {
                    forwarderStr = reader.readNullTerminatedString(forwardOffset);
                  } catch (_) {}
                }
              }

              exportsList.add(PeExport(
                name: expName,
                ordinal: base + ordIndex,
                rva: funcRva,
                forwarder: forwarderStr,
              ));
            }
          }
        }
      }
    }

    final dosHeader = PeDosHeader(
      magic: dosMagic,
      usedHeaderSize: 64, // Standard DOS size used by parser
      relocationOffset: reader.readUint16(24),
      peHeaderOffset: peHeaderOffset,
    );

    final ntHeaders = PeNtHeaders(
      signature: peSignature,
      coffHeader: coffHeader,
      optionalHeader: optionalHeader,
    );

    final peModel = PeModel(
      dosHeader: dosHeader,
      ntHeaders: ntHeaders,
      sections: sectionsList,
      imports: importsList,
      exports: exportsList,
    );

    // Map to common BinaryResult
    final architecture = _mapMachineToArch(machine);
    final bitness = isPE32Plus ? BinaryBitness.b64 : BinaryBitness.b32;
    final fileType = (characteristics & 0x2000 != 0) 
        ? BinaryFileType.sharedLibrary 
        : BinaryFileType.executable;

    final overview = BinaryOverview(
      fileName: fileName,
      fileSize: bytes.length,
      format: BinaryFormat.pe,
      architecture: architecture,
      bitness: bitness,
      endianness: BinaryEndianness.little, // PE is always little endian
      fileType: fileType,
      entryPoint: addressOfEntryPoint,
      formatIdentifier: isPE32Plus ? 'PE32+' : 'PE32',
    );

    final commonSections = sectionsList.map((sec) => BinarySection(
      name: sec.name,
      virtualAddress: sec.virtualAddress,
      virtualSize: sec.virtualSize,
      rawDataOffset: sec.rawDataOffset,
      rawDataSize: sec.rawDataSize,
      readable: sec.isReadable,
      writable: sec.isWritable,
      executable: sec.isExecutable,
      customProperties: {
        'characteristics': '0x${sec.characteristics.toRadixString(16).toUpperCase()}'
      },
    )).toList();

    final commonDeps = importsList.map((imp) => BinaryDependency(
      name: imp.dllName,
      importedSymbols: imp.functions.map((f) => f.name).toList(),
    )).toList();

    final commonSymbols = exportsList.map((exp) => BinarySymbol(
      name: exp.name,
      address: exp.rva,
      size: 0, // exports do not have a defined size field
      type: exp.forwarder != null ? 'Forwarder' : 'Export',
      binding: 'GLOBAL',
    )).toList();

    return BinaryResult(
      overview: overview,
      sections: commonSections,
      dependencies: commonDeps,
      symbols: commonSymbols,
      peData: peModel,
    );
  }

  static BinaryArchitecture _mapMachineToArch(int machine) {
    switch (machine) {
      case 0x014c: return BinaryArchitecture.x86;
      case 0x8664: return BinaryArchitecture.x64;
      case 0x01c0: return BinaryArchitecture.arm;
      case 0xaa64: return BinaryArchitecture.arm64;
      default: return BinaryArchitecture.unknown;
    }
  }
}
