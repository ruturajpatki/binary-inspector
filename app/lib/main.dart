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

import 'dart:io';
import 'package:flutter/material.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';

import 'app_theme.dart';
import 'details_view.dart';

void main() {
  runApp(const BinaryInspectorApp());
}

class BinaryInspectorApp extends StatelessWidget {
  const BinaryInspectorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Binary Inspector',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      home: const MainLayout(),
    );
  }
}

class MainLayout extends StatefulWidget {
  const MainLayout({super.key});

  @override
  State<MainLayout> createState() => _MainLayoutState();
}

class _MainLayoutState extends State<MainLayout> {
  BinaryResult? _result;
  String? _error;
  String _selectedNode = 'file_info';
  double _sidebarWidth = 260.0;
  bool _isDragging = false;

  Future<void> _openFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.any,
        dialogTitle: 'Select PE or ELF Binary',
      );
      if (result != null && result.files.single.path != null) {
        _loadFile(result.files.single.path!);
      }
    } catch (e) {
      setState(() {
        _error = 'Failed to pick file: $e';
      });
    }
  }

  void _loadFile(String path) {
    setState(() {
      _error = null;
    });

    try {
      final result = BinaryInspector.inspectFile(path);
      setState(() {
        _result = result;
        _selectedNode = 'file_info';
      });
    } on BinaryParserException catch (e) {
      setState(() {
        _result = null;
        _error = 'Parsing Error [${e.type.toUpperCase()}]: ${e.message}';
      });
    } catch (e) {
      setState(() {
        _result = null;
        _error = 'Unexpected Error: $e';
      });
    }
  }

  void _clearFile() {
    setState(() {
      _result = null;
      _error = null;
      _selectedNode = 'file_info';
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: DropTarget(
        onDragEntered: (_) => setState(() => _isDragging = true),
        onDragExited: (_) => setState(() => _isDragging = false),
        onDragDone: (details) {
          setState(() => _isDragging = false);
          if (details.files.isNotEmpty) {
            _loadFile(details.files.first.path);
          }
        },
        child: Stack(
          children: [
            Column(
              children: [
                _buildHeaderBar(),
                Expanded(
                  child: _error != null
                      ? _buildErrorState()
                      : _result == null
                          ? _buildEmptyState()
                          : _buildWorkspace(),
                ),
              ],
            ),
            if (_isDragging) _buildDragOverlay(),
          ],
        ),
      ),
    );
  }

  Widget _buildHeaderBar() {
    return Container(
      height: 60,
      padding: const EdgeInsets.symmetric(horizontal: 20),
      decoration: const BoxDecoration(
        color: AppTheme.sidebarBackground,
        border: Border(bottom: BorderSide(color: AppTheme.dividerColor)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Image.asset('assets/app-icon.png', width: 28, height: 28),
              const SizedBox(width: 12),
              const Text(
                'Binary Inspector',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 0.5,
                ),
              ),
              if (_result != null) ...[
                const SizedBox(width: 12),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppTheme.primary.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    _result!.overview.formatIdentifier,
                    style: const TextStyle(
                      fontSize: 11,
                      color: AppTheme.primary,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ]
            ],
          ),
          Row(
            children: [
              ElevatedButton.icon(
                icon: const Icon(Icons.file_open, size: 16),
                label: const Text('Open File'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primary,
                  foregroundColor: Colors.black,
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                ),
                onPressed: _openFile,
              ),
              const SizedBox(width: 8),
              ElevatedButton.icon(
                icon: const Icon(Icons.close, size: 16),
                label: const Text('Close File'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.redAccent,
                  foregroundColor: Colors.white,
                  disabledBackgroundColor: Colors.redAccent.withOpacity(0.2),
                  disabledForegroundColor: Colors.white.withOpacity(0.4),
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                ),
                onPressed: (_result != null || _error != null) ? _clearFile : null,
              ),
              const SizedBox(width: 8),
              OutlinedButton.icon(
                icon: const Icon(Icons.info_outline, size: 16),
                label: const Text('About'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppTheme.textPrimary,
                  side: const BorderSide(color: AppTheme.dividerColor),
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                ),
                onPressed: () => _showAboutDialog(context),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 450),
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: AppTheme.surface,
                shape: BoxShape.circle,
                border: Border.all(color: AppTheme.dividerColor),
              ),
              child: const Icon(
                Icons.upload_file_outlined,
                size: 72,
                color: AppTheme.textSecondary,
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Inspect Executable Binary',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: AppTheme.textPrimary),
            ),
            const SizedBox(height: 12),
            const Text(
              'Drag and drop any Windows PE (.exe, .dll, .sys) or Linux ELF executable here to view its headers, sections, imports, and exports.',
              textAlign: TextAlign.center,
              style: TextStyle(color: AppTheme.textSecondary, height: 1.5),
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              icon: const Icon(Icons.search, size: 18),
              label: const Text('Browse Files'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.primary,
                foregroundColor: Colors.black,
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
              ),
              onPressed: _openFile,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorState() {
    return Center(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 500),
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(20),
              decoration: const BoxDecoration(
                color: Colors.redAccent,
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.warning_amber_rounded,
                size: 48,
                color: Colors.white,
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Failed to Inspect Binary',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: AppTheme.textPrimary),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppTheme.surface,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: Colors.redAccent.withOpacity(0.3)),
              ),
              child: Text(
                _error!,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: AppTheme.textPrimary,
                  fontFamily: 'monospace',
                  fontFamilyFallback: ['Courier New', 'Consolas'],
                  fontSize: 12,
                  height: 1.5,
                ),
              ),
            ),
            const SizedBox(height: 24),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                OutlinedButton(
                  onPressed: _clearFile,
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppTheme.textPrimary,
                    side: const BorderSide(color: AppTheme.dividerColor),
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                  ),
                  child: const Text('Back'),
                ),
                const SizedBox(width: 12),
                ElevatedButton(
                  onPressed: _openFile,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.primary,
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                  ),
                  child: const Text('Try Another File'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildWorkspace() {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Sidebar Navigation
        Container(
          width: _sidebarWidth,
          color: AppTheme.sidebarBackground,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildSidebarOverviewHeader(),
              const Divider(height: 1),
              Expanded(
                child: ListView(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  children: _buildNavigationTree(),
                ),
              ),
            ],
          ),
        ),
        // Splitter handle
        GestureDetector(
          behavior: HitTestBehavior.translucent,
          onHorizontalDragUpdate: (details) {
            setState(() {
              _sidebarWidth = (_sidebarWidth + details.delta.dx).clamp(200.0, 450.0);
            });
          },
          child: MouseRegion(
            cursor: SystemMouseCursors.resizeLeftRight,
            child: Container(
              width: 4,
              color: AppTheme.dividerColor,
            ),
          ),
        ),
        // Details Area
        Expanded(
          child: DetailsView(
            result: _result!,
            selectedNode: _selectedNode,
          ),
        ),
      ],
    );
  }

  Widget _buildSidebarOverviewHeader() {
    final ov = _result!.overview;
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            ov.fileName,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: AppTheme.textPrimary),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 6),
          Text(
            '${ov.formatIdentifier} • ${ov.architecture.displayName} • ${(ov.fileSize / 1024).toStringAsFixed(1)} KB',
            style: const TextStyle(fontSize: 11, color: AppTheme.textSecondary),
          ),
        ],
      ),
    );
  }

  List<Widget> _buildNavigationTree() {
    final isPe = _result!.overview.format == BinaryFormat.pe;
    if (isPe) {
      return [
        _buildNavTile('Overview', 'file_info', Icons.info_outline),
        _buildNavHeader('Headers'),
        _buildNavTile('DOS Header', 'dos_header', Icons.list),
        _buildNavTile('NT Headers', 'nt_headers', Icons.view_headline),
        _buildNavTile('Optional Header', 'optional_header', Icons.settings),
        _buildNavHeader('Directories'),
        _buildNavTile('Sections', 'sections', Icons.dns_outlined),
        _buildNavTile('Imports (DLLs)', 'imports', Icons.downloading),
        _buildNavTile('Exports', 'exports', Icons.upload),
      ];
    } else {
      return [
        _buildNavTile('Overview', 'file_info', Icons.info_outline),
        _buildNavHeader('Headers'),
        _buildNavTile('ELF Header', 'elf_header', Icons.list),
        _buildNavTile('Program Headers', 'program_headers', Icons.view_headline),
        _buildNavHeader('Directories'),
        _buildNavTile('Sections', 'sections', Icons.dns_outlined),
        _buildNavTile('Dependencies', 'imports', Icons.downloading),
        _buildNavTile('Symbol Table', 'exports', Icons.upload),
      ];
    }
  }

  Widget _buildNavHeader(String title) {
    return Padding(
      padding: const EdgeInsets.only(left: 16, top: 16, bottom: 6),
      child: Text(
        title.toUpperCase(),
        style: const TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: AppTheme.textSecondary, letterSpacing: 1),
      ),
    );
  }

  Widget _buildNavTile(String title, String nodeId, IconData icon) {
    final isSelected = _selectedNode == nodeId;
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: isSelected ? AppTheme.primary.withOpacity(0.08) : Colors.transparent,
        borderRadius: BorderRadius.circular(4),
      ),
      child: ListTile(
        dense: true,
        horizontalTitleGap: 8,
        leading: Icon(
          icon,
          size: 16,
          color: isSelected ? AppTheme.primary : AppTheme.textSecondary,
        ),
        title: Text(
          title,
          style: TextStyle(
            fontSize: 13,
            color: isSelected ? AppTheme.primary : AppTheme.textPrimary,
            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
          ),
        ),
        onTap: () {
          setState(() {
            _selectedNode = nodeId;
          });
        },
      ),
    );
  }

  Widget _buildDragOverlay() {
    return Container(
      color: Colors.black.withOpacity(0.8),
      child: Center(
        child: Container(
          padding: const EdgeInsets.all(40),
          decoration: BoxDecoration(
            color: AppTheme.surface,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: AppTheme.primary, width: 2),
          ),
          child: const Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.download_rounded, size: 64, color: AppTheme.primary),
              SizedBox(height: 16),
              Text(
                'Drop binary here to inspect!',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: AppTheme.textPrimary),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _launchUrl(String url) {
    Process.run('cmd', ['/c', 'start', '', url]);
  }

  void _showAboutDialog(BuildContext context) {
    showDialog(
      context: context,
      barrierDismissible: true,
      builder: (BuildContext context) {
        return Dialog(
          backgroundColor: Colors.transparent,
          insetPadding: const EdgeInsets.symmetric(horizontal: 40, vertical: 24),
          child: Container(
            width: 420,
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: AppTheme.sidebarBackground,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: AppTheme.dividerColor),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.5),
                  blurRadius: 16,
                  offset: const Offset(0, 8),
                ),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    IconButton(
                      icon: const Icon(Icons.close, color: AppTheme.textSecondary, size: 20),
                      onPressed: () => Navigator.of(context).pop(),
                    ),
                  ],
                ),
                Image.asset(
                  'assets/app-icon.png',
                  width: 64,
                  height: 64,
                  fit: BoxFit.contain,
                ),
                const SizedBox(height: 16),
                const Text(
                  'Binary Inspector',
                  style: TextStyle(
                    fontSize: 22,
                    fontWeight: FontWeight.bold,
                    color: AppTheme.textPrimary,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'version 1.10',
                  style: TextStyle(
                    fontSize: 13,
                    color: AppTheme.primary.withOpacity(0.8),
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 16),
                const Divider(color: AppTheme.dividerColor, height: 1),
                const SizedBox(height: 16),
                const Text(
                  'A professional desktop utility and SDK\nfor programmatically inspecting Windows PE\nand Linux ELF binary layouts.',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 13,
                    color: AppTheme.textSecondary,
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 16),
                const Divider(color: AppTheme.dividerColor, height: 1),
                const SizedBox(height: 16),
                const Text(
                  'Developed by',
                  style: TextStyle(
                    fontSize: 11,
                    color: AppTheme.textSecondary,
                  ),
                ),
                const SizedBox(height: 4),
                const Text(
                  'Ruturaj V Patki',
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                    color: AppTheme.textPrimary,
                  ),
                ),
                const SizedBox(height: 20),
                _buildAboutLink(
                  icon: Icons.email_outlined,
                  label: 'assistance@ruturajpatki.com',
                  url: 'mailto:assistance@ruturajpatki.com',
                ),
                const SizedBox(height: 8),
                _buildAboutLink(
                  icon: Icons.language_outlined,
                  label: 'www.ruturajpatki.com',
                  url: 'https://www.ruturajpatki.com',
                ),
                const SizedBox(height: 8),
                _buildAboutLink(
                  icon: Icons.code_outlined,
                  label: 'github.com/ruturajpatki',
                  url: 'https://github.com/ruturajpatki',
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildAboutLink({required IconData icon, required String label, required String url}) {
    return InkWell(
      onTap: () => _launchUrl(url),
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 16, color: AppTheme.primary),
            const SizedBox(width: 8),
            Text(
              label,
              style: const TextStyle(
                fontSize: 13,
                color: AppTheme.primary,
                decoration: TextDecoration.underline,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
