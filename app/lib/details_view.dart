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
import 'package:binary_inspector_sdk/binary_inspector_sdk.dart';
import 'app_theme.dart';

class DetailsView extends StatefulWidget {
  final BinaryResult result;
  final String selectedNode;

  const DetailsView({
    super.key,
    required this.result,
    required this.selectedNode,
  });

  @override
  State<DetailsView> createState() => _DetailsViewState();
}

class _DetailsViewState extends State<DetailsView> {
  String _searchQuery = '';
  final TextEditingController _searchController = TextEditingController();

  @override
  void didUpdateWidget(covariant DetailsView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.selectedNode != widget.selectedNode) {
      _searchController.clear();
      _searchQuery = '';
    }
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    switch (widget.selectedNode) {
      case 'file_info':
        return _buildFileInfo();
      case 'sections':
        return _buildSections();
      case 'imports':
        return _buildImports();
      case 'exports':
        return _buildExportsSymbols();
      // PE Specific Nodes
      case 'dos_header':
        return _buildDosHeader();
      case 'nt_headers':
        return _buildNtHeaders();
      case 'optional_header':
        return _buildOptionalHeader();
      // ELF Specific Nodes
      case 'elf_header':
        return _buildElfHeader();
      case 'program_headers':
        return _buildElfProgramHeaders();
      default:
        return _buildFileInfo();
    }
  }

  Widget _buildSectionTitle(String title, [String? subtitle]) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: AppTheme.darkTheme.textTheme.titleLarge),
        if (subtitle != null) ...[
          const SizedBox(height: 4),
          Text(subtitle, style: AppTheme.darkTheme.textTheme.bodyMedium),
        ],
        const Divider(height: 24),
      ],
    );
  }

  Widget _buildCard({required String title, required List<Widget> children}) {
    return Card(
      color: AppTheme.cardBg,
      margin: const EdgeInsets.only(bottom: 16),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: const TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.bold,
                color: AppTheme.primary,
              ),
            ),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }

  Widget _buildRow(String name, String value, {bool isHex = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            flex: 2,
            child: Text(
              name,
              style: const TextStyle(fontWeight: FontWeight.w500, color: AppTheme.textSecondary),
            ),
          ),
          Expanded(
            flex: 3,
            child: SelectableText(
              value,
              style: isHex ? AppTheme.monoStyle : AppTheme.darkTheme.textTheme.bodyLarge,
            ),
          ),
        ],
      ),
    );
  }

  String _hex(int value, [int bytes = 4]) {
    final hexStr = value.toRadixString(16).toUpperCase();
    final padding = (bytes * 2) - hexStr.length;
    return '0x${padding > 0 ? '0' * padding : ''}$hexStr';
  }

  Widget _buildFileInfo() {
    final ov = widget.result.overview;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('File Information', 'Overview of the inspected binary'),
          _buildCard(
            title: 'General',
            children: [
              _buildRow('File Name', ov.fileName),
              _buildRow('File Size', '${(ov.fileSize / 1024).toStringAsFixed(2)} KB (${ov.fileSize} bytes)'),
              _buildRow('Binary Format', ov.format.displayName),
              _buildRow('Format Identifier', ov.formatIdentifier),
              _buildRow('Architecture', ov.architecture.displayName),
              _buildRow('Bitness', ov.bitness.displayName),
              _buildRow('Endianness', ov.endianness.displayName),
              _buildRow('File Type', ov.fileType.displayName),
              _buildRow('Entry Point Address', _hex(ov.entryPoint, ov.bitness == BinaryBitness.b64 ? 8 : 4), isHex: true),
            ],
          ),
          if (ov.format == BinaryFormat.pe) ...[
            _buildCard(
              title: 'PE Specific Information',
              children: [
                _buildRow('Subsystem', widget.result.peData?.ntHeaders.optionalHeader.subsystemName ?? 'Unknown'),
                _buildRow('DLL Characteristics', widget.result.peData?.ntHeaders.optionalHeader.dllCharacteristicsList.join(', ') ?? 'None'),
              ],
            ),
          ],
          if (ov.format == BinaryFormat.elf) ...[
            _buildCard(
              title: 'ELF Specific Information',
              children: [
                _buildRow('OS ABI', widget.result.elfData?.header.osAbiName ?? 'Unknown'),
                _buildRow('Dependencies Count', '${widget.result.dependencies.length}'),
                _buildRow('Symbols Count', '${widget.result.symbols.length}'),
              ],
            ),
          ]
        ],
      ),
    );
  }

  Widget _buildSections() {
    final filteredSections = widget.result.sections.where((sec) {
      return sec.name.toLowerCase().contains(_searchQuery.toLowerCase());
    }).toList();

    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('Sections', 'Total sections: ${widget.result.sections.length}'),
          _buildSearchField('Search sections...'),
          const SizedBox(height: 12),
          Expanded(
            child: filteredSections.isEmpty
                ? const Center(child: Text('No sections found.'))
                : ListView.builder(
                    itemCount: filteredSections.length,
                    itemBuilder: (context, index) {
                      final sec = filteredSections[index];
                      return Card(
                        color: AppTheme.cardBg,
                        margin: const EdgeInsets.only(bottom: 8),
                        child: ExpansionTile(
                          iconColor: AppTheme.primary,
                          collapsedIconColor: AppTheme.textSecondary,
                          title: Text(
                            sec.name,
                            style: const TextStyle(fontWeight: FontWeight.bold, color: AppTheme.primary),
                          ),
                          subtitle: Text(
                            'Addr: ${_hex(sec.virtualAddress)} | Raw Size: ${sec.rawDataSize} bytes',
                            style: AppTheme.darkTheme.textTheme.bodyMedium,
                          ),
                          children: [
                            Padding(
                              padding: const EdgeInsets.all(16.0),
                              child: Column(
                                children: [
                                  _buildRow('Virtual Address', _hex(sec.virtualAddress), isHex: true),
                                  _buildRow('Virtual Size', '${sec.virtualSize} bytes (${_hex(sec.virtualSize)})', isHex: true),
                                  _buildRow('Raw Data Offset', _hex(sec.rawDataOffset), isHex: true),
                                  _buildRow('Raw Data Size', '${sec.rawDataSize} bytes (${_hex(sec.rawDataSize)})', isHex: true),
                                  _buildRow('Permissions', '${sec.readable ? "Read " : ""}${sec.writable ? "Write " : ""}${sec.executable ? "Execute" : ""}'),
                                  if (sec.customProperties.isNotEmpty)
                                    ...sec.customProperties.entries.map((e) => _buildRow(e.key, e.value.toString())),
                                ],
                              ),
                            )
                          ],
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildImports() {
    final filteredDeps = widget.result.dependencies.where((dep) {
      return dep.name.toLowerCase().contains(_searchQuery.toLowerCase()) ||
          dep.importedSymbols.any((sym) => sym.toLowerCase().contains(_searchQuery.toLowerCase()));
    }).toList();

    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle(
            widget.result.overview.format == BinaryFormat.pe ? 'Imports (DLL Dependencies)' : 'Dynamic Shared Libraries',
            'Total dependencies: ${widget.result.dependencies.length}',
          ),
          _buildSearchField('Search library or imported function...'),
          const SizedBox(height: 12),
          Expanded(
            child: filteredDeps.isEmpty
                ? const Center(child: Text('No imports/dependencies found.'))
                : ListView.builder(
                    itemCount: filteredDeps.length,
                    itemBuilder: (context, index) {
                      final dep = filteredDeps[index];
                      final isPe = widget.result.overview.format == BinaryFormat.pe;
                      return Card(
                        color: AppTheme.cardBg,
                        margin: const EdgeInsets.only(bottom: 8),
                        child: ExpansionTile(
                          iconColor: AppTheme.primary,
                          collapsedIconColor: AppTheme.textSecondary,
                          title: Text(
                            dep.name,
                            style: const TextStyle(fontWeight: FontWeight.bold, color: AppTheme.primary),
                          ),
                          subtitle: isPe 
                              ? Text('Imports ${dep.importedSymbols.length} functions', style: AppTheme.darkTheme.textTheme.bodyMedium)
                              : Text('Required Library', style: AppTheme.darkTheme.textTheme.bodyMedium),
                          children: [
                            if (isPe && dep.importedSymbols.isNotEmpty)
                              Container(
                                constraints: const BoxConstraints(maxHeight: 250),
                                padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
                                child: ListView.builder(
                                  shrinkWrap: true,
                                  itemCount: dep.importedSymbols.length,
                                  itemBuilder: (context, fIndex) {
                                    return Padding(
                                      padding: const EdgeInsets.symmetric(vertical: 4.0),
                                      child: Text(
                                        dep.importedSymbols[fIndex],
                                        style: AppTheme.monoStyle,
                                      ),
                                    );
                                  },
                                ),
                              )
                            else if (isPe)
                              const Padding(
                                padding: EdgeInsets.all(16.0),
                                child: Text('No function name symbols resolved (imported by ordinal or IAT stripped).'),
                              )
                          ],
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildExportsSymbols() {
    final filteredSymbols = widget.result.symbols.where((sym) {
      return sym.name.toLowerCase().contains(_searchQuery.toLowerCase());
    }).toList();

    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle(
            widget.result.overview.format == BinaryFormat.pe ? 'Exports Table' : 'Symbol Table',
            'Total entry count: ${widget.result.symbols.length}',
          ),
          _buildSearchField('Search symbol/export name...'),
          const SizedBox(height: 12),
          Expanded(
            child: filteredSymbols.isEmpty
                ? const Center(child: Text('No symbols found.'))
                : Scrollbar(
                    interactive: true,
                    child: SingleChildScrollView(
                      scrollDirection: Axis.vertical,
                      child: SingleChildScrollView(
                        scrollDirection: Axis.horizontal,
                        child: DataTable(
                          columns: const [
                            DataColumn(label: Text('Name')),
                            DataColumn(label: Text('Address')),
                            DataColumn(label: Text('Size')),
                            DataColumn(label: Text('Type')),
                            DataColumn(label: Text('Binding')),
                          ],
                          rows: filteredSymbols.map((sym) {
                            return DataRow(cells: [
                              DataCell(
                                SelectableText(
                                  sym.name,
                                  style: const TextStyle(fontWeight: FontWeight.w600),
                                ),
                              ),
                              DataCell(SelectableText(_hex(sym.address), style: AppTheme.monoStyle)),
                              DataCell(Text(sym.size.toString())),
                              DataCell(Text(sym.type)),
                              DataCell(Text(sym.binding)),
                            ]);
                          }).toList(),
                        ),
                      ),
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildSearchField(String placeholder) {
    return TextField(
      controller: _searchController,
      style: const TextStyle(color: AppTheme.textPrimary),
      decoration: InputDecoration(
        hintText: placeholder,
        hintStyle: const TextStyle(color: AppTheme.textSecondary),
        prefixIcon: const Icon(Icons.search, color: AppTheme.textSecondary),
        suffixIcon: _searchQuery.isNotEmpty
            ? IconButton(
                icon: const Icon(Icons.clear, color: AppTheme.textSecondary),
                onPressed: () {
                  setState(() {
                    _searchController.clear();
                    _searchQuery = '';
                  });
                },
              )
            : null,
        filled: true,
        fillColor: AppTheme.surface,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: AppTheme.dividerColor),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: AppTheme.dividerColor),
        ),
      ),
      onChanged: (val) {
        setState(() {
          _searchQuery = val;
        });
      },
    );
  }

  // PE Header Details
  Widget _buildDosHeader() {
    final dos = widget.result.peData?.dosHeader;
    if (dos == null) return const Center(child: Text('DOS header data unavailable.'));
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('DOS Header', 'MS-DOS Legacy MZ Header'),
          _buildCard(
            title: 'Fields',
            children: [
              _buildRow('Magic Value (e_magic)', '${_hex(dos.magic, 2)} ("MZ")', isHex: true),
              _buildRow('Header size used', '${dos.usedHeaderSize} bytes'),
              _buildRow('Relocation Offset (e_lfarlc)', _hex(dos.relocationOffset, 2), isHex: true),
              _buildRow('PE Header Offset (e_lfanew)', '${_hex(dos.peHeaderOffset)} (${dos.peHeaderOffset} bytes)', isHex: true),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildNtHeaders() {
    final nt = widget.result.peData?.ntHeaders;
    if (nt == null) return const Center(child: Text('NT headers data unavailable.'));
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('NT / PE Headers', 'COFF and PE Signatures'),
          _buildCard(
            title: 'PE Signature',
            children: [
              _buildRow('Signature', '${_hex(nt.signature)} ("PE")', isHex: true),
            ],
          ),
          _buildCard(
            title: 'COFF File Header',
            children: [
              _buildRow('Machine Architecture', '${_hex(nt.coffHeader.machine, 2)} (${nt.coffHeader.machineName})', isHex: true),
              _buildRow('Number of Sections', '${nt.coffHeader.numberOfSections}'),
              _buildRow('Timestamp', '${nt.coffHeader.timeDateStamp} (${DateTime.fromMillisecondsSinceEpoch(nt.coffHeader.timeDateStamp * 1000).toUtc().toString()})'),
              _buildRow('Optional Header Size', '${nt.coffHeader.sizeOfOptionalHeader} bytes'),
              _buildRow('Characteristics Raw', _hex(nt.coffHeader.characteristics, 2), isHex: true),
              _buildRow('Characteristics List', nt.coffHeader.characteristicsList.join(', ')),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildOptionalHeader() {
    final opt = widget.result.peData?.ntHeaders.optionalHeader;
    if (opt == null) return const Center(child: Text('Optional header data unavailable.'));
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('Optional Header', 'COFF Optional Header Structure'),
          _buildCard(
            title: 'General',
            children: [
              _buildRow('Format Magic', '${_hex(opt.magic, 2)} (${opt.isPE32Plus ? "PE32+" : "PE32"})', isHex: true),
              _buildRow('Linker Version', '${opt.majorLinkerVersion}.${opt.minorLinkerVersion}'),
              _buildRow('Size of Executable Code', '${opt.sizeOfCode} bytes'),
              _buildRow('Size of Initialized Data', '${opt.sizeOfInitializedData} bytes'),
              _buildRow('Size of Uninitialized Data', '${opt.sizeOfUninitializedData} bytes'),
              _buildRow('Address of Entry Point (RVA)', _hex(opt.addressOfEntryPoint), isHex: true),
              _buildRow('Base of Code (RVA)', _hex(opt.baseOfCode), isHex: true),
              if (opt.baseOfData != null) _buildRow('Base of Data (RVA)', _hex(opt.baseOfData!), isHex: true),
              _buildRow('Image Base', _hex(opt.imageBase, opt.isPE32Plus ? 8 : 4), isHex: true),
            ],
          ),
          _buildCard(
            title: 'Windows Specific',
            children: [
              _buildRow('Section Alignment', '${opt.sectionAlignment} bytes'),
              _buildRow('File Alignment', '${opt.fileAlignment} bytes'),
              _buildRow('Subsystem Type', '${opt.subsystem} (${opt.subsystemName})'),
              _buildRow('OS Version', '${opt.majorOperatingSystemVersion}.${opt.minorOperatingSystemVersion}'),
              _buildRow('Image Version', '${opt.majorImageVersion}.${opt.minorImageVersion}'),
              _buildRow('Subsystem Version', '${opt.majorSubsystemVersion}.${opt.minorSubsystemVersion}'),
              _buildRow('Size of Image', '${opt.sizeOfImage} bytes'),
              _buildRow('Size of Headers', '${opt.sizeOfHeaders} bytes'),
              _buildRow('Checksum', _hex(opt.checkSum), isHex: true),
              _buildRow('DLL Characteristics Raw', _hex(opt.dllCharacteristics, 2), isHex: true),
              _buildRow('DLL Characteristics List', opt.dllCharacteristicsList.join(', ')),
              _buildRow('Stack Reserve', '${opt.sizeOfStackReserve} bytes'),
              _buildRow('Stack Commit', '${opt.sizeOfStackCommit} bytes'),
              _buildRow('Heap Reserve', '${opt.sizeOfHeapReserve} bytes'),
              _buildRow('Heap Commit', '${opt.sizeOfHeapCommit} bytes'),
            ],
          ),
          _buildCard(
            title: 'Data Directories Table',
            children: [
              Scrollbar(
                child: SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: DataTable(
                    columns: const [
                      DataColumn(label: Text('Directory Name')),
                      DataColumn(label: Text('Virtual Address (RVA)')),
                      DataColumn(label: Text('Size')),
                    ],
                    rows: opt.dataDirectories.map((dir) {
                      return DataRow(cells: [
                        DataCell(Text(dir.name, style: const TextStyle(fontWeight: FontWeight.bold))),
                        DataCell(Text(_hex(dir.virtualAddress), style: AppTheme.monoStyle)),
                        DataCell(Text('${dir.size} bytes')),
                      ]);
                    }).toList(),
                  ),
                ),
              )
            ],
          )
        ],
      ),
    );
  }

  // ELF Header Details
  Widget _buildElfHeader() {
    final elf = widget.result.elfData?.header;
    if (elf == null) return const Center(child: Text('ELF header data unavailable.'));
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('ELF Header', 'Executable and Linkable Format Header fields'),
          _buildCard(
            title: 'File Identification (e_ident)',
            children: [
              _buildRow('Magic bytes', elf.identMagic.map((e) => _hex(e, 1)).join(' ')),
              _buildRow('Class (e_ident[4])', '${elf.identClass} (${elf.className})'),
              _buildRow('Data Encoding (e_ident[5])', '${elf.identData} (${elf.endiannessName})'),
              _buildRow('OS ABI (e_ident[7])', '${elf.identOsAbi} (${elf.osAbiName})'),
              _buildRow('ABI Version (e_ident[8])', '${elf.identAbiVersion}'),
            ],
          ),
          _buildCard(
            title: 'ELF Fields',
            children: [
              _buildRow('Object File Type (e_type)', '${elf.type} (${elf.typeName})'),
              _buildRow('Machine Architecture (e_machine)', '${elf.machine} (${elf.machineName})'),
              _buildRow('Version (e_version)', '${elf.version}'),
              _buildRow('Entry Point Address (e_entry)', _hex(elf.entryPoint, elf.is64Bit ? 8 : 4), isHex: true),
              _buildRow('Program Header Table Offset (e_phoff)', '${elf.phOffset} bytes (${_hex(elf.phOffset)})', isHex: true),
              _buildRow('Section Header Table Offset (e_shoff)', '${elf.shOffset} bytes (${_hex(elf.shOffset)})', isHex: true),
              _buildRow('Processor Flags (e_flags)', _hex(elf.flags), isHex: true),
              _buildRow('ELF Header Size (e_ehsize)', '${elf.ehSize} bytes'),
              _buildRow('Program Header Size (e_phentsize)', '${elf.phEntrySize} bytes'),
              _buildRow('Program Header Count (e_phnum)', '${elf.phNum}'),
              _buildRow('Section Header Size (e_shentsize)', '${elf.shEntrySize} bytes'),
              _buildRow('Section Header Count (e_shnum)', '${elf.shNum}'),
              _buildRow('Section Header String Table Index (e_shstrndx)', '${elf.shStrNdx}'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildElfProgramHeaders() {
    final phs = widget.result.elfData?.programHeaders;
    if (phs == null || phs.isEmpty) return const Center(child: Text('No ELF program headers found.'));
    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionTitle('Program Headers', 'ELF Program segment headers list'),
          const SizedBox(height: 12),
          Expanded(
            child: ListView.builder(
              itemCount: phs.length,
              itemBuilder: (context, index) {
                final ph = phs[index];
                return Card(
                  color: AppTheme.cardBg,
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ExpansionTile(
                    iconColor: AppTheme.primary,
                    collapsedIconColor: AppTheme.textSecondary,
                    title: Text(
                      'Segment #$index: ${ph.typeName}',
                      style: const TextStyle(fontWeight: FontWeight.bold, color: AppTheme.primary),
                    ),
                    subtitle: Text(
                      'Offset: ${_hex(ph.offset)} | VirtAddr: ${_hex(ph.vaddr)} | Size: ${ph.filesz} bytes',
                      style: AppTheme.darkTheme.textTheme.bodyMedium,
                    ),
                    children: [
                      Padding(
                        padding: const EdgeInsets.all(16.0),
                        child: Column(
                          children: [
                            _buildRow('Type', ph.typeName),
                            _buildRow('Flags', '${ph.flagsString} (${_hex(ph.flags, 1)})', isHex: true),
                            _buildRow('File Offset', _hex(ph.offset), isHex: true),
                            _buildRow('Virtual Address', _hex(ph.vaddr), isHex: true),
                            _buildRow('Physical Address', _hex(ph.paddr), isHex: true),
                            _buildRow('File Size', '${ph.filesz} bytes'),
                            _buildRow('Memory Size', '${ph.memsz} bytes'),
                            _buildRow('Alignment', '${ph.align} bytes'),
                          ],
                        ),
                      )
                    ],
                  ),
                );
              },
            ),
          )
        ],
      ),
    );
  }
}
