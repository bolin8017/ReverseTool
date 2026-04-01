# Output Formats

ReverseTool produces structured output in JSONL and JSON formats. This document describes the full schema for each extractor.

## Output Directory Structure

When you run an extraction, results are organized per-binary:

```
output_directory/
  sample1/
    sample1.jsonl          # Opcode extraction output
  sample2/
    sample2.json           # Function call extraction output
  manifest.jsonl           # Run summary (all files)
```

The output directory defaults to `<input_directory>_output` unless overridden with `-o`.

## Opcode Extraction (JSONL)

Each binary produces a single-line JSONL file containing metadata and the full opcode sequence.

**File**: `<filename>.jsonl`

### Schema

```json
{
  "meta": {
    "extractor": "opcode",
    "backend": "<backend_name>",
    "file_name": "<original_filename>",
    "file_size": 14520,
    "sha256": "a1b2c3d4...",
    "md5": "d4e5f6a7...",
    "instruction_count": 1234
  },
  "opcodes": [
    {
      "index": 0,
      "addr": 4194356,
      "mnemonic": "nop",
      "instruction": "nop",
      "size": 1,
      "bytes": "90",
      "section": ".text"
    }
  ]
}
```

### Field Reference

#### `meta` Object

| Field | Type | Description |
|-------|------|-------------|
| `extractor` | string | Always `"opcode"` |
| `backend` | string | Backend used: `"ghidra"`, `"radare2"`, or `"idapro"` |
| `file_name` | string | Original binary filename |
| `file_size` | int | File size in bytes |
| `sha256` | string | SHA-256 hash of the binary |
| `md5` | string | MD5 hash of the binary |
| `instruction_count` | int | Total number of instructions extracted |
| `binary_info` | object | (optional) Architecture metadata from the backend |

#### `binary_info` Object (when present)

| Field | Type | Description |
|-------|------|-------------|
| `arch` | string | CPU architecture (e.g., `"x86"`, `"arm"`) |
| `bits` | int | Address size (e.g., `32`, `64`) |

#### `opcodes` Array Elements

| Field | Type | Description |
|-------|------|-------------|
| `index` | int | Zero-based instruction index |
| `addr` | int | Virtual address of the instruction |
| `mnemonic` | string | Instruction mnemonic (e.g., `"mov"`, `"call"`, `"nop"`) |
| `instruction` | string | Full instruction text with operands (e.g., `"mov rdi, rsp"`) |
| `size` | int | Instruction size in bytes |
| `bytes` | string | Raw instruction bytes as hex string |
| `section` | string | Section name containing the instruction (e.g., `".text"`) |

### Example

```json
{
  "meta": {
    "extractor": "opcode",
    "backend": "radare2",
    "file_name": "sample",
    "file_size": 14520,
    "sha256": "a1b2c3d4e5f6...",
    "md5": "d4e5f6a7b8c9...",
    "instruction_count": 3,
    "binary_info": { "arch": "x86", "bits": 64 }
  },
  "opcodes": [
    { "index": 0, "addr": 4194356, "mnemonic": "nop", "instruction": "nop", "size": 1, "bytes": "90", "section": ".text" },
    { "index": 1, "addr": 4194360, "mnemonic": "mov", "instruction": "mov rdi, rsp", "size": 3, "bytes": "4889e7", "section": ".text" },
    { "index": 2, "addr": 4194363, "mnemonic": "call", "instruction": "call 0x401050", "size": 5, "bytes": "e8a8000000", "section": ".text" }
  ]
}
```

## Function Call Extraction (JSON)

Each binary produces a JSON file containing function metadata, a call graph, and a DOT representation.

**File**: `<filename>.json`

### Schema

```json
{
  "meta": {
    "extractor": "function_call",
    "backend": "<backend_name>",
    "file_name": "<original_filename>",
    "file_size": 14520,
    "sha256": "a1b2c3d4...",
    "md5": "d4e5f6a7...",
    "function_count": 12
  },
  "call_graph": {
    "directed": true,
    "nodes": [ ... ],
    "functions": { ... }
  },
  "dot": "digraph code { ... }"
}
```

### Field Reference

#### `meta` Object

| Field | Type | Description |
|-------|------|-------------|
| `extractor` | string | Always `"function_call"` |
| `backend` | string | Backend used: `"ghidra"`, `"radare2"`, or `"idapro"` |
| `file_name` | string | Original binary filename |
| `file_size` | int | File size in bytes |
| `sha256` | string | SHA-256 hash of the binary |
| `md5` | string | MD5 hash of the binary |
| `function_count` | int | Total number of functions detected |

#### `call_graph` Object

| Field | Type | Description |
|-------|------|-------------|
| `directed` | bool | Always `true` -- the call graph is a directed graph |
| `nodes` | array | List of node objects (one per function) |
| `functions` | object | Map of address to function details |

#### `nodes` Array Elements

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Function address as hex string (e.g., `"0x1000"`) |
| `label` | string | Function name or address if unnamed |
| `instruction_count` | int | Number of instructions in this function |
| `instructions` | array | List of instruction strings |
| `is_external` | bool | (optional) Whether the function is an external/imported symbol |

#### `functions` Object

Keyed by hex address string. Each value contains:

| Field | Type | Description |
|-------|------|-------------|
| `function_name` | string | Demangled or raw function name |
| `instructions` | array | List of instruction strings (e.g., `["push rbp", "ret"]`) |
| `is_external` | bool | (optional) `true` for imported/external functions, `false` for local |

#### `dot` Field

A [Graphviz DOT](https://graphviz.org/doc/info/lang.html) string representing the call graph. Can be rendered directly:

```bash
# Extract and render
jq -r '.dot' output/sample/sample.json | dot -Tpng -o callgraph.png
```

#### `is_external` Behavior

The `is_external` field indicates whether a function is an imported symbol (from a shared library) or defined locally in the binary:

- **Ghidra**: Detects external functions via the `ExternalManager` API
- **Radare2**: Marks functions with `imp.` prefix as external
- **IDA Pro**: Uses segment analysis to detect import table entries

> **Note**: Backend results may differ. Ghidra typically detects more external references than Radare2. See [docs/backends.md](backends.md) for details.

### Example

```json
{
  "meta": {
    "extractor": "function_call",
    "backend": "radare2",
    "file_name": "sample",
    "file_size": 14520,
    "sha256": "a1b2c3d4e5f6...",
    "md5": "d4e5f6a7b8c9...",
    "function_count": 2
  },
  "call_graph": {
    "directed": true,
    "nodes": [
      { "id": "0x1000", "label": "main", "instruction_count": 4, "instructions": ["push rbp", "mov rbp, rsp", "call 0x1050", "ret"] },
      { "id": "0x1050", "label": "helper", "instruction_count": 2, "instructions": ["push rbp", "ret"], "is_external": false }
    ],
    "functions": {
      "0x1000": { "function_name": "main", "instructions": ["push rbp", "mov rbp, rsp", "call 0x1050", "ret"] },
      "0x1050": { "function_name": "helper", "instructions": ["push rbp", "ret"], "is_external": false }
    }
  },
  "dot": "digraph code {\n  \"0x1000\" [label=\"main\"];\n  \"0x1050\" [label=\"helper\"];\n  \"0x1000\" -> \"0x1050\";\n}"
}
```

## Manifest (JSONL)

After each extraction run, a `manifest.jsonl` file is written to the output directory root. Each line is a JSON object summarizing one processed file.

**File**: `manifest.jsonl`

### Schema

```json
{
  "file_name": "sample",
  "file_path": "/path/to/binaries/sample",
  "status": "success",
  "cpu_time_sec": 1.2345,
  "wall_time_sec": 2.5678,
  "output_files": ["/path/to/output/sample/sample.jsonl"],
  "timestamp": "2026-01-15T10:30:00+00:00"
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `file_name` | string | Original binary filename |
| `file_path` | string | Absolute path to the input binary |
| `status` | string | `"success"` or `"error"` |
| `cpu_time_sec` | float | CPU time consumed (seconds) |
| `wall_time_sec` | float | Wall-clock time (seconds) |
| `output_files` | array | Absolute paths of generated output files |
| `timestamp` | string | ISO 8601 timestamp (UTC) |
| `error` | string | (only when `status` is `"error"`) Error message |

The manifest is useful for batch processing pipelines to verify completeness and identify failures.
