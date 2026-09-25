## 1.11.0

- **Exports & Symbol Table Scrollbar Fix**:
  - Resolved desktop scrollbar crash (`The Scrollbar's ScrollController has no ScrollPosition attached`) on the Exports Table by introducing dedicated, managed `ScrollController` instances.
  - Implemented responsive bidirectional (vertical and horizontal) scrollbars with explicit orientations and depth notification predicates.
  - Added layout constraints ensuring table contents fill available viewport width while allowing horizontal overflow scrolling.
  - Attached a dedicated scroll controller to the PE Optional Header Data Directories table.
  - Added automatic reset of scroll offsets when switching nodes or applying search filters.
- **Window Centering on Startup**:
  - Automatically centers the application window on the user's active monitor upon launch, factoring in multi-monitor setups, taskbar exclusion (`rcWork`), and per-monitor DPI scaling without startup visual jitter.
- **UI & Warning Cleanup**:
  - Wrapped navigation tiles in `Material` to resolve `ListTile` background color and ink splash warnings on Windows.
- **Testing**:
  - Added automated widget tests covering the Exports Table scrollbars and scroll interactions.

## 1.10.0

- Initial version.
