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

class BinaryReader {
  final Uint8List bytes;
  final ByteData data;
  Endian defaultEndian;

  BinaryReader(this.bytes, {this.defaultEndian = Endian.little})
      : data = ByteData.sublistView(bytes);

  int get length => bytes.length;

  void checkBounds(int offset, int size) {
    if (offset < 0 || size < 0 || offset + size > bytes.length) {
      throw const BinaryParserException('Attempted to read out of bounds.', 'truncated');
    }
  }

  int readUint8(int offset) {
    checkBounds(offset, 1);
    return data.getUint8(offset);
  }

  int readUint16(int offset, [Endian? endian]) {
    checkBounds(offset, 2);
    return data.getUint16(offset, endian ?? defaultEndian);
  }

  int readUint32(int offset, [Endian? endian]) {
    checkBounds(offset, 4);
    return data.getUint32(offset, endian ?? defaultEndian);
  }

  int readUint64(int offset, [Endian? endian]) {
    checkBounds(offset, 8);
    return data.getUint64(offset, endian ?? defaultEndian);
  }

  int readInt32(int offset, [Endian? endian]) {
    checkBounds(offset, 4);
    return data.getInt32(offset, endian ?? defaultEndian);
  }

  String readString(int offset, int maxLength) {
    checkBounds(offset, maxLength);
    final codes = <int>[];
    for (var i = 0; i < maxLength; i++) {
      final code = bytes[offset + i];
      if (code == 0) break;
      codes.add(code);
    }
    return String.fromCharCodes(codes);
  }

  String readNullTerminatedString(int offset) {
    if (offset < 0 || offset >= bytes.length) {
      throw const BinaryParserException('String offset out of bounds.', 'invalid_binary');
    }
    final codes = <int>[];
    var current = offset;
    while (current < bytes.length) {
      final code = bytes[current++];
      if (code == 0) break;
      codes.add(code);
    }
    return String.fromCharCodes(codes);
  }
}
