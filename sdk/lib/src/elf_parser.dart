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
import 'elf_models.dart';

class ElfParser {
  static bool detect(Uint8List bytes) {
    if (bytes.length < 4) return false;
    return bytes[0] == 0x7F &&
           bytes[1] == 0x45 && // 'E'
           bytes[2] == 0x4C && // 'L'
           bytes[3] == 0x46;   // 'F'
  }

  static BinaryResult parse(Uint8List bytes, String fileName) {
    final reader = BinaryReader(bytes, defaultEndian: Endian.little);

    if (bytes.length < 52) {
      throw const BinaryParserException('File size is too small to be an ELF binary.', 'truncated');
    }

    if (!detect(bytes)) {
      throw const BinaryParserException('Invalid ELF magic header.', 'invalid_binary');
    }

    final identMagic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    final identClass = reader.readUint8(4);
    final identData = reader.readUint8(5);
    final identVersion = reader.readUint8(6);
    final identOsAbi = reader.readUint8(7);
    final identAbiVersion = reader.readUint8(8);

    if (identClass != 1 && identClass != 2) {
      throw BinaryParserException('Unsupported ELF class: $identClass', 'unsupported');
    }
    if (identData != 1 && identData != 2) {
      throw BinaryParserException('Unsupported ELF data encoding (endianness): $identData', 'unsupported');
    }

    final is64Bit = identClass == 2;
    final isLittleEndian = identData == 1;
    reader.defaultEndian = isLittleEndian ? Endian.little : Endian.big;

    final int type = reader.readUint16(16);
    final int machine = reader.readUint16(18);
    final int version = reader.readUint32(20);

    int entryPoint;
    int phOffset;
    int shOffset;
    int flags;
    int ehSize;
    int phEntrySize;
    int phNum;
    int shEntrySize;
    int shNum;
    int shStrNdx;

    if (!is64Bit) {
      // ELF32
      entryPoint = reader.readUint32(24);
      phOffset = reader.readUint32(28);
      shOffset = reader.readUint32(32);
      flags = reader.readUint32(36);
      ehSize = reader.readUint16(40);
      phEntrySize = reader.readUint16(42);
      phNum = reader.readUint16(44);
      shEntrySize = reader.readUint16(46);
      shNum = reader.readUint16(48);
      shStrNdx = reader.readUint16(50);
    } else {
      // ELF64
      if (bytes.length < 64) {
        throw const BinaryParserException('File size is too small for ELF64 header.', 'truncated');
      }
      entryPoint = reader.readUint64(24);
      phOffset = reader.readUint64(32);
      shOffset = reader.readUint64(40);
      flags = reader.readUint32(48);
      ehSize = reader.readUint16(52);
      phEntrySize = reader.readUint16(54);
      phNum = reader.readUint16(56);
      shEntrySize = reader.readUint16(58);
      shNum = reader.readUint16(60);
      shStrNdx = reader.readUint16(62);
    }

    final header = ElfHeader(
      identMagic: identMagic,
      identClass: identClass,
      identData: identData,
      identVersion: identVersion,
      identOsAbi: identOsAbi,
      identAbiVersion: identAbiVersion,
      type: type,
      machine: machine,
      version: version,
      entryPoint: entryPoint,
      phOffset: phOffset,
      shOffset: shOffset,
      flags: flags,
      ehSize: ehSize,
      phEntrySize: phEntrySize,
      phNum: phNum,
      shEntrySize: shEntrySize,
      shNum: shNum,
      shStrNdx: shStrNdx,
    );

    // Parse Program Headers
    final phList = <ElfProgramHeader>[];
    if (phOffset != 0 && phNum > 0) {
      if (phOffset + (phNum * phEntrySize) > bytes.length) {
        // Truncated program headers table
        phNum = (bytes.length - phOffset) ~/ phEntrySize;
      }
      for (var i = 0; i < phNum; i++) {
        final phEntryOffset = phOffset + (i * phEntrySize);
        if (phEntryOffset < 0 || phEntryOffset + phEntrySize > bytes.length) break;

        if (!is64Bit) {
          // ELF32 Program Header
          final pType = reader.readUint32(phEntryOffset);
          final pOffset = reader.readUint32(phEntryOffset + 4);
          final pVaddr = reader.readUint32(phEntryOffset + 8);
          final pPaddr = reader.readUint32(phEntryOffset + 12);
          final pFilesz = reader.readUint32(phEntryOffset + 16);
          final pMemsz = reader.readUint32(phEntryOffset + 20);
          final pFlags = reader.readUint32(phEntryOffset + 24);
          final pAlign = reader.readUint32(phEntryOffset + 28);

          phList.add(ElfProgramHeader(
            type: pType,
            flags: pFlags,
            offset: pOffset,
            vaddr: pVaddr,
            paddr: pPaddr,
            filesz: pFilesz,
            memsz: pMemsz,
            align: pAlign,
          ));
        } else {
          // ELF64 Program Header
          final pType = reader.readUint32(phEntryOffset);
          final pFlags = reader.readUint32(phEntryOffset + 4);
          final pOffset = reader.readUint64(phEntryOffset + 8);
          final pVaddr = reader.readUint64(phEntryOffset + 16);
          final pPaddr = reader.readUint64(phEntryOffset + 24);
          final pFilesz = reader.readUint64(phEntryOffset + 32);
          final pMemsz = reader.readUint64(phEntryOffset + 40);
          final pAlign = reader.readUint64(phEntryOffset + 48);

          phList.add(ElfProgramHeader(
            type: pType,
            flags: pFlags,
            offset: pOffset,
            vaddr: pVaddr,
            paddr: pPaddr,
            filesz: pFilesz,
            memsz: pMemsz,
            align: pAlign,
          ));
        }
      }
    }

    // Parse Section Headers
    final rawShList = <_RawSectionHeader>[];
    if (shOffset != 0 && shNum > 0) {
      if (shOffset + (shNum * shEntrySize) > bytes.length) {
        shNum = (bytes.length - shOffset) ~/ shEntrySize;
      }
      for (var i = 0; i < shNum; i++) {
        final shEntryOffset = shOffset + (i * shEntrySize);
        if (shEntryOffset < 0 || shEntryOffset + shEntrySize > bytes.length) break;

        if (!is64Bit) {
          // ELF32 Section Header
          final shName = reader.readUint32(shEntryOffset);
          final shType = reader.readUint32(shEntryOffset + 4);
          final shFlags = reader.readUint32(shEntryOffset + 8);
          final shAddr = reader.readUint32(shEntryOffset + 12);
          final shFileOffset = reader.readUint32(shEntryOffset + 16);
          final shSize = reader.readUint32(shEntryOffset + 20);
          final shLink = reader.readUint32(shEntryOffset + 24);
          final shInfo = reader.readUint32(shEntryOffset + 28);
          final shAddralign = reader.readUint32(shEntryOffset + 32);
          final shEntsize = reader.readUint32(shEntryOffset + 36);

          rawShList.add(_RawSectionHeader(
            nameIndex: shName,
            type: shType,
            flags: shFlags,
            addr: shAddr,
            offset: shFileOffset,
            size: shSize,
            link: shLink,
            info: shInfo,
            addralign: shAddralign,
            entsize: shEntsize,
          ));
        } else {
          // ELF64 Section Header
          final shName = reader.readUint32(shEntryOffset);
          final shType = reader.readUint32(shEntryOffset + 4);
          final shFlags = reader.readUint64(shEntryOffset + 8);
          final shAddr = reader.readUint64(shEntryOffset + 16);
          final shFileOffset = reader.readUint64(shEntryOffset + 24);
          final shSize = reader.readUint64(shEntryOffset + 32);
          final shLink = reader.readUint32(shEntryOffset + 40);
          final shInfo = reader.readUint32(shEntryOffset + 44);
          final shAddralign = reader.readUint64(shEntryOffset + 48);
          final shEntsize = reader.readUint64(shEntryOffset + 56);

          rawShList.add(_RawSectionHeader(
            nameIndex: shName,
            type: shType,
            flags: shFlags,
            addr: shAddr,
            offset: shFileOffset,
            size: shSize,
            link: shLink,
            info: shInfo,
            addralign: shAddralign,
            entsize: shEntsize,
          ));
        }
      }
    }

    // Resolve Section Names
    final shList = <ElfSectionHeader>[];

    for (var i = 0; i < rawShList.length; i++) {
      final rawSec = rawShList[i];
      var name = '.section_$i';
      if (shStrNdx >= 0 && shStrNdx < rawShList.length) {
        final shstrtabHeader = rawShList[shStrNdx];
        final nameOffset = shstrtabHeader.offset + rawSec.nameIndex;
        if (nameOffset < bytes.length && nameOffset >= shstrtabHeader.offset && nameOffset < shstrtabHeader.offset + shstrtabHeader.size) {
          try {
            name = reader.readNullTerminatedString(nameOffset);
          } catch (_) {}
        }
      }
      shList.add(ElfSectionHeader(
        name: name,
        nameIndex: rawSec.nameIndex,
        type: rawSec.type,
        flags: rawSec.flags,
        addr: rawSec.addr,
        offset: rawSec.offset,
        size: rawSec.size,
        link: rawSec.link,
        info: rawSec.info,
        addralign: rawSec.addralign,
        entsize: rawSec.entsize,
      ));
    }

    // Parse Symbols (both static symtab and dynamic dynsym)
    final symbolsList = <ElfSymbol>[];
    for (final sec in shList) {
      if (sec.type == 2 || sec.type == 11) { // SHT_SYMTAB or SHT_DYNSYM
        final strtabIndex = sec.link;
        if (strtabIndex >= 0 && strtabIndex < shList.length) {
          final strtabSec = shList[strtabIndex];
          var symOffset = sec.offset;
          final symSize = is64Bit ? 24 : 16;
          final numSyms = sec.size ~/ symSize;

          if (symOffset + (numSyms * symSize) <= bytes.length) {
            for (var i = 0; i < numSyms; i++) {
              final symEntryOffset = symOffset + (i * symSize);
              int nameIndex;
              int value;
              int size;
              int info;
              int other;
              int shndx;

              if (!is64Bit) {
                // ELF32 Symbol
                nameIndex = reader.readUint32(symEntryOffset);
                value = reader.readUint32(symEntryOffset + 4);
                size = reader.readUint32(symEntryOffset + 8);
                info = reader.readUint8(symEntryOffset + 12);
                other = reader.readUint8(symEntryOffset + 13);
                shndx = reader.readUint16(symEntryOffset + 14);
              } else {
                // ELF64 Symbol
                nameIndex = reader.readUint32(symEntryOffset);
                info = reader.readUint8(symEntryOffset + 4);
                other = reader.readUint8(symEntryOffset + 5);
                shndx = reader.readUint16(symEntryOffset + 6);
                value = reader.readUint64(symEntryOffset + 8);
                size = reader.readUint64(symEntryOffset + 16);
              }

              var symName = '';
              if (nameIndex != 0) {
                final symNameOffset = strtabSec.offset + nameIndex;
                if (symNameOffset >= strtabSec.offset && symNameOffset < strtabSec.offset + strtabSec.size && symNameOffset < bytes.length) {
                  try {
                    symName = reader.readNullTerminatedString(symNameOffset);
                  } catch (_) {}
                }
              }

              if (symName.isNotEmpty) {
                symbolsList.add(ElfSymbol(
                  name: symName,
                  nameIndex: nameIndex,
                  value: value,
                  size: size,
                  info: info,
                  other: other,
                  shndx: shndx,
                ));
              }
            }
          }
        }
      }
    }

    // Parse Dynamic entries & dependencies (DT_NEEDED)
    final dynamicEntries = <ElfDynamicEntry>[];
    final dependencies = <String>[];

    for (final sec in shList) {
      if (sec.type == 6) { // SHT_DYNAMIC
        var dynOffset = sec.offset;
        final entrySize = is64Bit ? 16 : 8;
        final linkIndex = sec.link; // Points to string table for DT_NEEDED strings

        if (dynOffset + entrySize <= bytes.length) {
          while (dynOffset + entrySize <= bytes.length) {
            int tag;
            int value;

            if (!is64Bit) {
              tag = reader.readInt32(dynOffset);
              value = reader.readUint32(dynOffset + 4);
            } else {
              tag = reader.readUint64(dynOffset);
              value = reader.readUint64(dynOffset + 8);
            }

            if (tag == 0) break; // DT_NULL

            dynamicEntries.add(ElfDynamicEntry(tag: tag, value: value));

            if (tag == 1 && linkIndex >= 0 && linkIndex < shList.length) { // DT_NEEDED
              final strtabSec = shList[linkIndex];
              final strOffset = strtabSec.offset + value;
              if (strOffset >= strtabSec.offset && strOffset < strtabSec.offset + strtabSec.size && strOffset < bytes.length) {
                try {
                  final libName = reader.readNullTerminatedString(strOffset);
                  if (libName.isNotEmpty) {
                    dependencies.add(libName);
                  }
                } catch (_) {}
              }
            }

            dynOffset += entrySize;
          }
        }
      }
    }

    final elfModel = ElfModel(
      header: header,
      programHeaders: phList,
      sectionHeaders: shList,
      dynamicEntries: dynamicEntries,
      dependencies: dependencies,
      symbols: symbolsList,
    );

    // Map to common BinaryResult
    final architecture = _mapMachineToArch(machine);
    final bitness = is64Bit ? BinaryBitness.b64 : BinaryBitness.b32;
    final endianness = isLittleEndian ? BinaryEndianness.little : BinaryEndianness.big;

    BinaryFileType fileType = BinaryFileType.unknown;
    if (type == 1) {
      fileType = BinaryFileType.objectFile;
    } else if (type == 2) {
      fileType = BinaryFileType.executable;
    } else if (type == 3) {
      fileType = BinaryFileType.sharedLibrary;
    }

    final overview = BinaryOverview(
      fileName: fileName,
      fileSize: bytes.length,
      format: BinaryFormat.elf,
      architecture: architecture,
      bitness: bitness,
      endianness: endianness,
      fileType: fileType,
      entryPoint: entryPoint,
      formatIdentifier: is64Bit ? 'ELF64' : 'ELF32',
    );

    final commonSections = shList.map((sec) => BinarySection(
      name: sec.name.isEmpty ? '.section' : sec.name,
      virtualAddress: sec.addr,
      virtualSize: sec.size,
      rawDataOffset: sec.offset,
      rawDataSize: sec.size,
      readable: sec.isAllocated, // Allocated sections are loaded to memory (readable)
      writable: sec.isWritable,
      executable: sec.isExecutable,
      customProperties: {
        'type': sec.typeName,
        'flags': '0x${sec.flags.toRadixString(16).toUpperCase()}',
      },
    )).toList();

    final commonDeps = dependencies.map((dep) => BinaryDependency(
      name: dep,
      importedSymbols: const [], // ELF dynamic dependencies are loaded DLL names
    )).toList();

    final commonSymbols = symbolsList.map((sym) => BinarySymbol(
      name: sym.name,
      address: sym.value,
      size: sym.size,
      type: sym.typeName,
      binding: sym.bindingName,
    )).toList();

    return BinaryResult(
      overview: overview,
      sections: commonSections,
      dependencies: commonDeps,
      symbols: commonSymbols,
      elfData: elfModel,
    );
  }

  static BinaryArchitecture _mapMachineToArch(int machine) {
    switch (machine) {
      case 3: return BinaryArchitecture.x86;
      case 62: return BinaryArchitecture.x64;
      case 40: return BinaryArchitecture.arm;
      case 183: return BinaryArchitecture.arm64;
      default: return BinaryArchitecture.unknown;
    }
  }
}

class _RawSectionHeader {
  final int nameIndex;
  final int type;
  final int flags;
  final int addr;
  final int offset;
  final int size;
  final int link;
  final int info;
  final int addralign;
  final int entsize;

  const _RawSectionHeader({
    required this.nameIndex,
    required this.type,
    required this.flags,
    required this.addr,
    required this.offset,
    required this.size,
    required this.link,
    required this.info,
    required this.addralign,
    required this.entsize,
  });
}
