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

class AppTheme {
  static const Color background = Color(0xFF0D0F12);
  static const Color sidebarBackground = Color(0xFF15181E);
  static const Color surface = Color(0xFF1E222B);
  static const Color cardBg = Color(0xFF252A34);
  
  static const Color primary = Color(0xFF00ADB5);
  static const Color accent = Color(0xFF00E676);
  static const Color error = Color(0xFFFF5252);
  
  static const Color textPrimary = Color(0xFFECEFF4);
  static const Color textSecondary = Color(0xFF8F9AA9);
  static const Color dividerColor = Color(0xFF2C323F);

  static ThemeData get darkTheme {
    return ThemeData.dark().copyWith(
      scaffoldBackgroundColor: background,
      primaryColor: primary,
      colorScheme: const ColorScheme.dark(
        primary: primary,
        secondary: accent,
        error: error,
        surface: surface,
      ),
      dividerTheme: const DividerThemeData(
        color: dividerColor,
        thickness: 1,
      ),
      scrollbarTheme: ScrollbarThemeData(
        thumbColor: WidgetStateProperty.all(primary.withOpacity(0.5)),
        trackColor: WidgetStateProperty.all(Colors.transparent),
        radius: const Radius.circular(4),
      ),
      textTheme: const TextTheme(
        bodyLarge: TextStyle(color: textPrimary, fontSize: 14),
        bodyMedium: TextStyle(color: textSecondary, fontSize: 13),
        titleLarge: TextStyle(color: textPrimary, fontSize: 18, fontWeight: FontWeight.bold),
        titleMedium: TextStyle(color: textPrimary, fontSize: 15, fontWeight: FontWeight.w600),
      ),
    );
  }

  static TextStyle get monoStyle {
    return const TextStyle(
      fontFamily: 'monospace',
      fontFamilyFallback: ['Courier New', 'Consolas'],
      color: accent,
      fontWeight: FontWeight.w500,
    );
  }
}
