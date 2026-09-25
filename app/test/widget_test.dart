/*
 * Project: Binary Inspector
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

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';
import 'package:app/main.dart';
import 'package:app/details_view.dart';

void main() {
  testWidgets('App starts with a beautiful empty state', (WidgetTester tester) async {
    // Configure desktop-like window size for the test
    tester.view.physicalSize = const Size(1280, 720);
    tester.view.devicePixelRatio = 1.0;

    // Build our app and trigger a frame.
    await tester.pumpWidget(const BinaryInspectorApp());

    // Verify empty state is displayed
    expect(find.text('Inspect Executable Binary'), findsOneWidget);
    expect(find.text('Browse Files'), findsOneWidget);
    
    // Verify there is an "Open File" button in the header bar
    expect(find.text('Open File'), findsOneWidget);
  });

  testWidgets('Exports table scrollbar is present, interactive, and scrollable without error', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1280, 720);
    tester.view.devicePixelRatio = 1.0;

    final mockSymbols = List.generate(
      100,
      (i) => BinarySymbol(
        name: 'ExportFunction_$i',
        address: 0x140001000 + i * 16,
        size: 32,
        type: 'Function',
        binding: 'Global',
      ),
    );

    final mockResult = BinaryResult(
      overview: const BinaryOverview(
        fileName: 'test.dll',
        fileSize: 102400,
        format: BinaryFormat.pe,
        formatIdentifier: 'PE32+',
        architecture: BinaryArchitecture.x64,
        bitness: BinaryBitness.b64,
        endianness: BinaryEndianness.little,
        fileType: BinaryFileType.sharedLibrary,
        entryPoint: 0x140001000,
      ),
      sections: const [],
      dependencies: const [],
      symbols: mockSymbols,
    );

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: DetailsView(
            result: mockResult,
            selectedNode: 'exports',
          ),
        ),
      ),
    );

    await tester.pumpAndSettle();

    // Verify Exports Table header is displayed
    expect(find.text('Exports Table'), findsOneWidget);
    expect(find.text('Total entry count: 100'), findsOneWidget);

    // Verify first row is visible
    expect(find.text('ExportFunction_0'), findsOneWidget);

    // Verify Scrollbars are present
    expect(find.byType(Scrollbar), findsAtLeastNWidgets(2));

    // Scroll down using drag
    await tester.drag(find.text('ExportFunction_0'), const Offset(0, -500));
    await tester.pumpAndSettle();

    // Verify that scrolling occurred without throwing scroll position exception
    expect(tester.takeException(), isNull);
  });
}
