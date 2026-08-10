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
import 'package:test/test.dart';
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';

void main() {
  group('Binary Format Detection', () {
    test('Detects invalid / empty inputs', () {
      final empty = Uint8List(0);
      expect(BinaryInspector.detectFormat(empty), equals(BinaryFormat.unknown));

      final random = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(BinaryInspector.detectFormat(random), equals(BinaryFormat.unknown));
    });

    test('Detects PE format signature', () {
      final peBytes = Uint8List(128);
      // DOS Header: e_magic = 'MZ'
      peBytes[0] = 0x4D;
      peBytes[1] = 0x5A;
      // e_lfanew = 0x40
      peBytes[60] = 0x40;
      // PE signature = 'PE\0\0'
      peBytes[0x40] = 0x50;
      peBytes[0x40 + 1] = 0x45;

      expect(BinaryInspector.detectFormat(peBytes), equals(BinaryFormat.pe));
    });

    test('Detects ELF format signature', () {
      final elfBytes = Uint8List.fromList([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1]);
      expect(BinaryInspector.detectFormat(elfBytes), equals(BinaryFormat.elf));
    });
  });

  group('PE Parser Tests', () {
    test('Throws on truncated/invalid PE header', () {
      final badPe = Uint8List(70);
      badPe[0] = 0x4D;
      badPe[1] = 0x5A;
      badPe[60] = 0x40; // e_lfanew points to 64
      // We don't write PE signature, so it should throw invalid format exception
      expect(
        () => BinaryInspector.inspectBytes(badPe, 'test.exe'),
        throwsA(isA<BinaryParserException>()),
      );
    });

    test('Parses a mock PE32+ (64-bit) binary successfully', () {
      final peBytes = Uint8List(512);
      
      // DOS Header
      peBytes[0] = 0x4D; // M
      peBytes[1] = 0x5A; // Z
      // relocation offset
      peBytes[24] = 0x40;
      // e_lfanew = 64
      peBytes[60] = 64;

      // NT Header (64)
      peBytes[64] = 0x50; // P
      peBytes[65] = 0x45; // E
      peBytes[66] = 0;
      peBytes[67] = 0;

      // COFF Header (68)
      // Machine = AMD64 (0x8664)
      peBytes[68] = 0x64;
      peBytes[69] = 0x86;
      // Number of sections = 1
      peBytes[70] = 1;
      // TimeDateStamp = 0x60000000
      peBytes[72] = 0;
      peBytes[73] = 0;
      peBytes[74] = 0;
      peBytes[75] = 0x60;
      // Size of optional header = 240 (0xF0)
      peBytes[84] = 0xF0;
      peBytes[85] = 0;
      // Characteristics = 0x0022
      peBytes[86] = 0x22;
      peBytes[87] = 0;

      // Optional Header (88)
      // Magic = PE32+ (0x20b)
      peBytes[88] = 0x0B;
      peBytes[89] = 0x02;
      // AddressOfEntryPoint = 0x1000
      peBytes[88 + 16] = 0x00;
      peBytes[88 + 17] = 0x10;
      // ImageBase = 0x0000000140000000 (64-bit)
      peBytes[88 + 24] = 0x00;
      peBytes[88 + 25] = 0x00;
      peBytes[88 + 26] = 0x00;
      peBytes[88 + 27] = 0x00;
      peBytes[88 + 28] = 0x00;
      peBytes[88 + 29] = 0x00;
      peBytes[88 + 30] = 0x00;
      peBytes[88 + 31] = 0x40; // 0x4000000000
      // SectionAlignment = 0x1000
      peBytes[88 + 32] = 0x00;
      peBytes[88 + 33] = 0x10;
      // FileAlignment = 0x200
      peBytes[88 + 36] = 0x00;
      peBytes[88 + 37] = 0x02;
      // Subsystem = Windows GUI (2)
      peBytes[88 + 68] = 2;
      // NumberOfRvaAndSizes = 16
      peBytes[88 + 108] = 16;

      // Data Directories (starts at 88 + 112 = 200)
      // Let's populate Import Directory (index 1, offset 200 + 8 = 208)
      // Import RVA = 0x2000, Size = 40 (0x28)
      peBytes[208] = 0x00;
      peBytes[209] = 0x20; // 0x2000
      peBytes[212] = 0x28; // size 40

      // Section Header (starts at 88 + 240 = 328)
      // Name = ".text\0\0\0"
      peBytes[328] = 0x2E; // .
      peBytes[329] = 0x74; // t
      peBytes[330] = 0x65; // e
      peBytes[331] = 0x78; // x
      peBytes[332] = 0x74; // t
      // VirtualSize = 0x1000
      peBytes[328 + 8] = 0x00;
      peBytes[328 + 9] = 0x10;
      // VirtualAddress = 0x1000
      peBytes[328 + 12] = 0x00;
      peBytes[328 + 13] = 0x10;
      // SizeOfRawData = 0x200
      peBytes[328 + 16] = 0x00;
      peBytes[328 + 17] = 0x02;
      // PointerToRawData = 0x200
      peBytes[328 + 20] = 0x00;
      peBytes[328 + 21] = 0x02;
      // Characteristics = MEM_EXECUTE | MEM_READ (0x60000020)
      peBytes[328 + 36] = 0x20;
      peBytes[328 + 39] = 0x60;

      final result = BinaryInspector.inspectBytes(peBytes, 'mock_app.exe');

      expect(result.overview.format, equals(BinaryFormat.pe));
      expect(result.overview.bitness, equals(BinaryBitness.b64));
      expect(result.overview.architecture, equals(BinaryArchitecture.x64));
      expect(result.overview.fileType, equals(BinaryFileType.executable));
      expect(result.sections.length, equals(1));
      expect(result.sections[0].name, equals('.text'));
      expect(result.sections[0].executable, isTrue);
      expect(result.sections[0].readable, isTrue);
      expect(result.sections[0].writable, isFalse);
    });
  });

  group('ELF Parser Tests', () {
    test('Throws on truncated/invalid ELF Header', () {
      final badElf = Uint8List.fromList([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1]);
      expect(
        () => BinaryInspector.inspectBytes(badElf, 'test.so'),
        throwsA(isA<BinaryParserException>()),
      );
    });

    test('Parses a mock ELF64 (64-bit) binary successfully', () {
      final elfBytes = Uint8List(128);

      // ELF Magic
      elfBytes[0] = 0x7F;
      elfBytes[1] = 0x45;
      elfBytes[2] = 0x4C;
      elfBytes[3] = 0x46;
      // Class = ELF64 (2)
      elfBytes[4] = 2;
      // Data = Little Endian (1)
      elfBytes[5] = 1;
      // Version = 1
      elfBytes[6] = 1;

      // Type = Shared Object (3)
      elfBytes[16] = 3;
      elfBytes[17] = 0;
      // Machine = AMD64 (62)
      elfBytes[18] = 62;
      elfBytes[19] = 0;

      // Entrypoint = 0x1000 (8 bytes at 24)
      elfBytes[24] = 0x00;
      elfBytes[25] = 0x10;

      // Program headers offset = 64
      elfBytes[32] = 64;

      // Section headers offset = 0 (none for now to test robustness)
      elfBytes[40] = 0;

      // EhSize = 64
      elfBytes[52] = 64;
      // PhEntrySize = 56
      elfBytes[54] = 56;
      // PhNum = 1
      elfBytes[56] = 1;

      final result = BinaryInspector.inspectBytes(elfBytes, 'mock_lib.so');

      expect(result.overview.format, equals(BinaryFormat.elf));
      expect(result.overview.bitness, equals(BinaryBitness.b64));
      expect(result.overview.endianness, equals(BinaryEndianness.little));
      expect(result.overview.architecture, equals(BinaryArchitecture.x64));
      expect(result.overview.fileType, equals(BinaryFileType.sharedLibrary));
    });
  });
}
