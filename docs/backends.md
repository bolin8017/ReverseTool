# Backend Details

ReverseTool supports three reverse engineering backends. Each has different strengths, requirements, and behavior. This document covers the internals of each backend and their differences.

## Ghidra 12.0.4

### How It Works

ReverseTool uses **PyGhidra** (v3.0.2) to run Ghidra analysis in a subprocess. For each binary:

1. A temporary project directory is created
2. A Python launcher script invokes `pyghidra.run_script()` with the binary and an extractor-specific Ghidra script
3. The Ghidra script runs inside the Ghidra analysis engine, writes results to a temp file
4. ReverseTool reads the results and cleans up the temp directory

The session object (`GhidraSession`) is a lightweight container holding the `analyzeHeadless` path, input file, and timeout. No persistent Ghidra process is kept alive between files.

### Version Detection

Version is read from `<ghidra_root>/Ghidra/application.properties`:

```
application.version=12.0.4
```

The `analyzeHeadless` binary is expected at `<ghidra_root>/support/analyzeHeadless`. ReverseTool resolves the root directory by navigating two levels up from the `analyzeHeadless` path.

### Requirements

- Ghidra 12.0+ (tested with 12.0.4)
- JDK 21 (full JDK, not JRE)
- PyGhidra 3.0.2
- `analyzeHeadless` on PATH or specified via `--ghidra-path` / config file

### Timeout Handling

Analysis is wrapped with GNU `timeout`. If a binary exceeds the configured timeout, the subprocess is killed and a `BackendTimeout` exception is raised.

## Radare2 6.1.2

### How It Works

ReverseTool uses **r2pipe** (v1.9.8) to communicate with Radare2 via a pipe-based IPC channel. For each binary:

1. `r2pipe.open()` launches an `r2` process with `-2` flag (suppress stderr)
2. The analysis timeout is set via `e anal.timeout=<timeout>`
3. Extractor commands are sent via `r2.cmd()` and `r2.cmdj()` (JSON output)
4. The r2 process is closed via `r2.quit()`

The session object (`Radare2Session`) wraps the active r2pipe connection and the input file path.

### Version Detection

Version is detected by running `r2 -v` and parsing the first line:

```
radare2 6.1.2 ...
```

### Requirements

- Radare2 6.1+ (tested with 6.1.2)
- r2pipe Python package (v1.9.8)
- `r2` binary on PATH

### Analysis Level

The Radare2 analysis depth is configurable:

| Level | Command | Description |
|-------|---------|-------------|
| `a` | `a` | Basic analysis (fastest) |
| `aa` | `aa` | Standard analysis (default) |
| `aaa` | `aaa` | Deep analysis (slowest, most complete) |

Configure via `~/.config/reverse-tool/config.toml`:

```toml
[backends.radare2]
analysis_level = "aa"
```

## IDA Pro 9.3+

### How It Works

ReverseTool uses **idat** (IDA's command-line processor) to run IDAPython scripts in batch mode. For each binary:

1. A temporary directory is created for the IDA database and output
2. `idat` is launched with `-A` (autonomous mode), `-c` (create new database), and `-S<script>` flags
3. The IDAPython script extracts data and writes results to the temp directory
4. ReverseTool reads the results and cleans up

The session object (`IdaproSession`) is a lightweight container holding the `idat` path, input file, and timeout. Like Ghidra, no persistent process is maintained.

### Version Detection

Version is read from `<ida_root>/python/ida_pro.py` by searching for the pattern:

```
IDA SDK v9.3
```

### Requirements

- IDA Pro 9.3+ (commercial license required)
- `idat` binary on PATH or specified via `--ida-path` / config file
- **Local-only**: Cannot be bundled in Docker images due to licensing

### License Considerations

IDA Pro is proprietary software. ReverseTool:
- Does **not** bundle or redistribute any IDA Pro files
- Only invokes `idat` as an external subprocess
- Requires the user to have a valid IDA Pro license

### Environment Variables

The IDA subprocess is configured with:

| Variable | Value | Purpose |
|----------|-------|---------|
| `QT_QPA_PLATFORM` | `offscreen` | Prevent GUI initialization |
| `TVHEADLESS` | `1` | Enable headless mode |
| `_RT_OUTPUT` | (temp path) | Output file location |
| `_RT_BINARY` | (input path) | Binary being analyzed |

## Backend Comparison

| Feature | Ghidra 12.0.4 | Radare2 6.1.2 | IDA Pro 9.3+ |
|---------|---------------|---------------|--------------|
| License | Apache 2.0 | LGPL-3.0 | Commercial |
| Docker support | Yes | Yes | No (local-only) |
| Session type | Subprocess per file | Persistent r2pipe | Subprocess per file |
| Analysis depth | Full auto-analysis | Configurable (`a`/`aa`/`aaa`) | Full auto-analysis |
| `is_external` detection | ExternalManager API | `imp.` prefix heuristic | Segment analysis |
| Startup overhead | High (JVM + Ghidra) | Low (native binary) | Medium (database creation) |
| Memory usage | High (~1 GB+) | Low (~100 MB) | Medium (~500 MB) |

## Known Differences Between Backends

Different backends may produce different results for the same binary. This is expected and stems from differences in analysis algorithms.

### Instruction Counts

Ghidra and IDA Pro typically detect more instructions than Radare2, particularly in:
- Exception handlers and unwind tables
- Padding/alignment bytes that Ghidra interprets as instructions
- Overlapping instructions (e.g., x86 instruction aliasing)

### Function Detection

- **Ghidra** tends to detect more functions via its aggressive function identification heuristics
- **Radare2** function detection depends on the analysis level (`aa` vs `aaa`)
- **IDA Pro** uses signature-based detection (FLIRT) and produces results between Ghidra and Radare2

### External Function Detection

The `is_external` field in function call output may differ:
- **Ghidra**: Uses the `ExternalManager` API which tracks imported symbols at the program level
- **Radare2**: Uses a naming heuristic -- functions with the `imp.` prefix are marked external
- **IDA Pro**: Analyzes segment types to identify import table entries

For cross-backend consistency in downstream analysis, consider normalizing external detection using a common heuristic (e.g., matching against a known import database).
