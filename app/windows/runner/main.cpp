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

#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <windows.h>

#include "flutter_window.h"
#include "utils.h"

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  flutter::DartProject project(L"data");

  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();

  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1280, 720);
  if (!window.Create(L"Binary Inspector", origin, size)) {
    return EXIT_FAILURE;
  }

  // Center the window on the active screen's work area (excluding taskbar)
  HWND hwnd = window.GetHandle();
  if (hwnd) {
    HMONITOR target_monitor = nullptr;
    POINT cursor_pos;
    if (::GetCursorPos(&cursor_pos)) {
      target_monitor = ::MonitorFromPoint(cursor_pos, MONITOR_DEFAULTTONEAREST);
    } else {
      target_monitor = ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    }

    MONITORINFO monitor_info = {};
    monitor_info.cbSize = sizeof(MONITORINFO);
    if (::GetMonitorInfo(target_monitor, &monitor_info)) {
      RECT window_rect = {};
      ::GetWindowRect(hwnd, &window_rect);
      int window_width = window_rect.right - window_rect.left;
      int window_height = window_rect.bottom - window_rect.top;
      int work_width = monitor_info.rcWork.right - monitor_info.rcWork.left;
      int work_height = monitor_info.rcWork.bottom - monitor_info.rcWork.top;

      int new_width = (window_width > work_width) ? work_width : window_width;
      int new_height = (window_height > work_height) ? work_height : window_height;
      int x = monitor_info.rcWork.left + (work_width - new_width) / 2;
      int y = monitor_info.rcWork.top + (work_height - new_height) / 2;

      UINT flags = SWP_NOZORDER | SWP_NOACTIVATE;
      if (new_width == window_width && new_height == window_height) {
        flags |= SWP_NOSIZE;
      }
      ::SetWindowPos(hwnd, nullptr, x, y, new_width, new_height, flags);
    }
  }

  window.SetQuitOnClose(true);

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
