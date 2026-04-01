"""Ghidra postScript for function call graph and disassembly extraction.

Runs inside Ghidra's PyGhidra environment (Ghidra 12.0+).
"""
import json
import os

argv = getScriptArgs()

if len(argv) < 1:
    raise ValueError("Missing argument: output folder path")

output_folder = argv[0]
program = currentProgram
file_name = program.getName()

fm = program.getFunctionManager()
func_list = list(fm.getFunctions(True))

if not func_list:
    raise Exception(f"{file_name}: No functions found")

function_call_graph = ["digraph code {"]
functions_info = {}

for func in func_list:
    entry_point = func.getEntryPoint()
    entry_offset = hex(entry_point.getOffset())
    name = func.getName()
    # isExternal() only catches pure external symbols without bodies.
    # isThunk() catches PLT stubs and import trampolines.
    is_external = func.isExternal() or func.isThunk()

    label = f"[EXT] {name}" if is_external else name
    functions_info[entry_offset] = {
        "function_name": name,
        "is_external": is_external,
        "instructions": []
    }

    function_call_graph.append(f'  "{entry_offset}" [label="{label}"];')

    # Extract call edges — direct calls
    callees = func.getCalledFunctions(None)
    seen_targets = set()
    for callee in callees:
        callee_offset = hex(callee.getEntryPoint().getOffset())
        function_call_graph.append(f'  "{entry_offset}" -> "{callee_offset}";')
        seen_targets.add(callee_offset)

    # Extract instructions and check for computed/indirect calls in one pass
    body = func.getBody()
    if body is not None and not body.isEmpty() and not is_external:
        try:
            for instr in program.getListing().getInstructions(body, True):
                functions_info[entry_offset]["instructions"].append(str(instr))
                for ref in instr.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        target = hex(ref.getToAddress().getOffset())
                        if target not in seen_targets:
                            function_call_graph.append(
                                f'  "{entry_offset}" -> "{target}" [style=dashed];'
                            )
                            seen_targets.add(target)
        except Exception as e:
            print(f"WARNING: {file_name}: Error extracting instructions for {name}: {e}")

function_call_graph.append("}")

if not functions_info:
    raise Exception(f"{file_name}: No function information extracted")

# Write DOT file
dot_path = os.path.join(output_folder, file_name + '.dot')
with open(dot_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(function_call_graph))

# Write JSON file
json_path = os.path.join(output_folder, file_name + '.json')
with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(functions_info, f, indent=4)
