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

class ElfModel {
  final ElfHeader header;
  final List<ElfProgramHeader> programHeaders;
  final List<ElfSectionHeader> sectionHeaders;
  final List<ElfDynamicEntry> dynamicEntries;
  final List<String> dependencies;
  final List<ElfSymbol> symbols;

  const ElfModel({
    required this.header,
    required this.programHeaders,
    required this.sectionHeaders,
    required this.dynamicEntries,
    required this.dependencies,
    required this.symbols,
  });
}

class ElfHeader {
  final List<int> identMagic;   // Should be [0x7f, 0x45, 0x4c, 0x46] (0x7F 'ELF')
  final int identClass;         // 1 = 32-bit, 2 = 64-bit
  final int identData;          // 1 = Little Endian, 2 = Big Endian
  final int identVersion;
  final int identOsAbi;
  final int identAbiVersion;
  final int type;               // e_type
  final int machine;            // e_machine
  final int version;            // e_version
  final int entryPoint;         // e_entry (32-bit or 64-bit)
  final int phOffset;           // e_phoff
  final int shOffset;           // e_shoff
  final int flags;              // e_flags
  final int ehSize;             // e_ehsize
  final int phEntrySize;        // e_phentsize
  final int phNum;              // e_phnum
  final int shEntrySize;        // e_shentsize
  final int shNum;              // e_shnum
  final int shStrNdx;           // e_shstrndx

  const ElfHeader({
    required this.identMagic,
    required this.identClass,
    required this.identData,
    required this.identVersion,
    required this.identOsAbi,
    required this.identAbiVersion,
    required this.type,
    required this.machine,
    required this.version,
    required this.entryPoint,
    required this.phOffset,
    required this.shOffset,
    required this.flags,
    required this.ehSize,
    required this.phEntrySize,
    required this.phNum,
    required this.shEntrySize,
    required this.shNum,
    required this.shStrNdx,
  });

  bool get is64Bit => identClass == 2;
  bool get isLittleEndian => identData == 1;

  String get className => identClass == 1 ? 'ELF32' : (identClass == 2 ? 'ELF64' : 'Unknown Class ($identClass)');
  String get endiannessName => identData == 1 ? 'Little Endian' : (identData == 2 ? 'Big Endian' : 'Unknown Endian ($identData)');
  
  String get osAbiName {
    switch (identOsAbi) {
      case 0: return 'System V / UNIX';
      case 1: return 'HP-UX';
      case 2: return 'NetBSD';
      case 3: return 'Linux';
      case 6: return 'Solaris';
      case 7: return 'AIX';
      case 8: return 'IRIX';
      case 9: return 'FreeBSD';
      case 12: return 'OpenBSD';
      default: return 'Unknown OS ABI ($identOsAbi)';
    }
  }

  String get typeName {
    switch (type) {
      case 0: return 'NONE (No file type)';
      case 1: return 'REL (Relocatable file)';
      case 2: return 'EXEC (Executable file)';
      case 3: return 'DYN (Shared object file)';
      case 4: return 'CORE (Core file)';
      default: return 'Unknown Type ($type)';
    }
  }

  String get machineName {
    switch (machine) {
      case 3: return 'Intel 80386 (x86)';
      case 40: return 'ARM (32-bit)';
      case 62: return 'Advanced Micro Devices X86-64';
      case 183: return 'ARM 64-bit (AArch64)';
      default: return 'Unknown Machine ($machine)';
    }
  }
}

class ElfProgramHeader {
  final int type;               // p_type
  final int flags;              // p_flags
  final int offset;             // p_offset
  final int vaddr;              // p_vaddr
  final int paddr;              // p_paddr
  final int filesz;             // p_filesz
  final int memsz;              // p_memsz
  final int align;              // p_align

  const ElfProgramHeader({
    required this.type,
    required this.flags,
    required this.offset,
    required this.vaddr,
    required this.paddr,
    required this.filesz,
    required this.memsz,
    required this.align,
  });

  String get typeName {
    switch (type) {
      case 0: return 'NULL';
      case 1: return 'LOAD';
      case 2: return 'DYNAMIC';
      case 3: return 'INTERP';
      case 4: return 'NOTE';
      case 5: return 'SHLIB';
      case 6: return 'PHDR';
      case 7: return 'TLS';
      case 0x6474e550: return 'GNU_EH_FRAME';
      case 0x6474e551: return 'GNU_STACK';
      case 0x6474e552: return 'GNU_RELRO';
      default: return '0x${type.toRadixString(16).toUpperCase()}';
    }
  }

  bool get isReadable => flags & 4 != 0;
  bool get isWritable => flags & 2 != 0;
  bool get isExecutable => flags & 1 != 0;

  String get flagsString {
    final r = isReadable ? 'R' : '-';
    final w = isWritable ? 'W' : '-';
    final x = isExecutable ? 'X' : '-';
    return '$r$w$x';
  }
}

class ElfSectionHeader {
  final String name;            // Derived from sh_name and string table
  final int nameIndex;          // sh_name
  final int type;               // sh_type
  final int flags;              // sh_flags
  final int addr;               // sh_addr
  final int offset;             // sh_offset
  final int size;               // sh_size
  final int link;               // sh_link
  final int info;               // sh_info
  final int addralign;          // sh_addralign
  final int entsize;            // sh_entsize

  const ElfSectionHeader({
    required this.name,
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

  String get typeName {
    switch (type) {
      case 0: return 'NULL';
      case 1: return 'PROGBITS';
      case 2: return 'SYMTAB';
      case 3: return 'STRTAB';
      case 4: return 'RELA';
      case 5: return 'HASH';
      case 6: return 'DYNAMIC';
      case 7: return 'NOTE';
      case 8: return 'NOBITS';
      case 9: return 'REL';
      case 10: return 'SHLIB';
      case 11: return 'DYNSYM';
      case 14: return 'INIT_ARRAY';
      case 15: return 'FINI_ARRAY';
      case 16: return 'PREINIT_ARRAY';
      case 17: return 'GROUP';
      case 18: return 'SYMTAB_SHNDX';
      default: return '0x${type.toRadixString(16).toUpperCase()}';
    }
  }

  bool get isWritable => flags & 1 != 0;      // SHF_WRITE
  bool get isAllocated => flags & 2 != 0;     // SHF_ALLOC
  bool get isExecutable => flags & 4 != 0;    // SHF_EXECINSTR

  List<String> get flagsList {
    final list = <String>[];
    if (flags & 1 != 0) list.add('WRITE');
    if (flags & 2 != 0) list.add('ALLOC');
    if (flags & 4 != 0) list.add('EXEC');
    if (flags & 0x10 != 0) list.add('MERGE');
    if (flags & 0x20 != 0) list.add('STRINGS');
    if (flags & 0x40 != 0) list.add('INFO_LINK');
    if (flags & 0x80 != 0) list.add('LINK_ORDER');
    if (flags & 0x100 != 0) list.add('OS_NONCONFORMING');
    if (flags & 0x200 != 0) list.add('GROUP');
    if (flags & 0x400 != 0) list.add('TLS');
    return list;
  }
}

class ElfDynamicEntry {
  final int tag;                // d_tag (e.g. 1 = DT_NEEDED, 2 = DT_PLTRELSZ)
  final int value;              // d_un.d_val or d_un.d_ptr

  const ElfDynamicEntry({
    required this.tag,
    required this.value,
  });

  String get tagName {
    switch (tag) {
      case 0: return 'NULL';
      case 1: return 'NEEDED';
      case 2: return 'PLTRELSZ';
      case 3: return 'PLTGOT';
      case 4: return 'HASH';
      case 5: return 'STRTAB';
      case 6: return 'SYMTAB';
      case 7: return 'RELA';
      case 8: return 'RELASZ';
      case 9: return 'RELAENT';
      case 10: return 'STRSZ';
      case 11: return 'SYMENT';
      case 12: return 'INIT';
      case 13: return 'FINI';
      case 14: return 'SONAME';
      case 15: return 'RPATH';
      case 16: return 'SYMBOLIC';
      case 17: return 'REL';
      case 18: return 'RELSZ';
      case 19: return 'RELENT';
      case 20: return 'PLTREL';
      case 21: return 'DEBUG';
      case 22: return 'TEXTREL';
      case 23: return 'JMPREL';
      case 24: return 'BIND_NOW';
      case 25: return 'INIT_ARRAY';
      case 26: return 'FINI_ARRAY';
      case 27: return 'INIT_ARRAYSZ';
      case 28: return 'FINI_ARRAYSZ';
      case 29: return 'RUNPATH';
      case 30: return 'FLAGS';
      default: return 'TAG_$tag';
    }
  }
}

class ElfSymbol {
  final String name;            // Resolved symbol name
  final int nameIndex;          // st_name
  final int value;              // st_value
  final int size;               // st_size
  final int info;               // st_info (binding + type)
  final int other;              // st_other (visibility)
  final int shndx;              // st_shndx

  const ElfSymbol({
    required this.name,
    required this.nameIndex,
    required this.value,
    required this.size,
    required this.info,
    required this.other,
    required this.shndx,
  });

  int get bindingType => info >> 4;
  int get symbolType => info & 0xf;

  String get bindingName {
    switch (bindingType) {
      case 0: return 'LOCAL';
      case 1: return 'GLOBAL';
      case 2: return 'WEAK';
      default: return 'NUM_$bindingType';
    }
  }

  String get typeName {
    switch (symbolType) {
      case 0: return 'NOTYPE';
      case 1: return 'OBJECT';
      case 2: return 'FUNC';
      case 3: return 'SECTION';
      case 4: return 'FILE';
      case 5: return 'COMMON';
      case 6: return 'TLS';
      default: return 'NUM_$symbolType';
    }
  }

  String get visibilityName {
    switch (other & 3) {
      case 0: return 'DEFAULT';
      case 1: return 'INTERNAL';
      case 2: return 'HIDDEN';
      case 3: return 'PROTECTED';
      default: return 'UNKNOWN';
    }
  }
}
