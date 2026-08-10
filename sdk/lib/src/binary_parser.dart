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

import 'dart:io';
import 'dart:typed_data';
import 'binary_models.dart';
import 'pe_parser.dart';
import 'elf_parser.dart';

class BinaryInspector {
  /// Detect the binary format from raw bytes.
  static BinaryFormat detectFormat(Uint8List bytes) {
    if (PeParser.detect(bytes)) return BinaryFormat.pe;
    if (ElfParser.detect(bytes)) return BinaryFormat.elf;
    return BinaryFormat.unknown;
  }

  /// Load and parse a binary from a file path.
  static BinaryResult inspectFile(String filePath) {
    final file = File(filePath);
    if (!file.existsSync()) {
      throw BinaryParserException('File does not exist: $filePath', 'io_error');
    }
    
    Uint8List bytes;
    try {
      bytes = file.readAsBytesSync();
    } catch (e) {
      throw BinaryParserException('Failed to read file: $e', 'io_error');
    }

    // Extract filename safely
    final name = file.uri.pathSegments.isNotEmpty 
        ? file.uri.pathSegments.last 
        : 'unknown_file';
        
    return inspectBytes(bytes, name);
  }

  /// Parse a binary directly from a byte array.
  static BinaryResult inspectBytes(Uint8List bytes, String fileName) {
    final format = detectFormat(bytes);
    switch (format) {
      case BinaryFormat.pe:
        return PeParser.parse(bytes, fileName);
      case BinaryFormat.elf:
        return ElfParser.parse(bytes, fileName);
      case BinaryFormat.unknown:
        throw const BinaryParserException(
          'Unsupported or unknown binary format. Magic bytes did not match PE or ELF.',
          'unknown_format'
        );
    }
  }
}
