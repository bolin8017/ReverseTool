"""IDAPython script for function call graph and disassembly extraction.

Runs inside IDA Pro 9.x headless (idat -A -S).
Reads _RT_OUTPUT env var for output folder path.
"""
import json
import os
import sys

import ida_auto
import ida_funcs
import ida_pro
import ida_xref
import idc
import idautils


def main():
    ida_auto.auto_wait()

    output_folder = os.environ.get("_RT_OUTPUT")
    if not output_folder:
        print("ERROR: _RT_OUTPUT environment variable not set", file=sys.stderr)
        ida_pro.qexit(1)
        return

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    file_name = idc.get_input_file_path()
    base_name = os.path.basename(file_name)

    function_call_graph = ["digraph code {"]
    functions_info = {}

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if func is None:
            continue

        entry_offset = hex(func.start_ea)
        name = ida_funcs.get_func_name(func_ea)
        # FUNC_LIB: FLIRT-matched library functions
        # FUNC_THUNK: PLT/import stub functions
        is_external = bool(func.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))

        label = "[EXT] " + name if is_external else name
        functions_info[entry_offset] = {
            "function_name": name,
            "is_external": is_external,
            "instructions": [],
        }

        function_call_graph.append('  "{}" [label="{}"];'.format(entry_offset, label))

        # Collect call targets for this function
        seen_targets = set()

        # Iterate instructions in this function
        if not is_external:
            ea = func.start_ea
            while ea < func.end_ea and ea != idc.BADADDR:
                flags = idc.get_full_flags(ea)
                if idc.is_code(flags):
                    disasm = idc.GetDisasm(ea)
                    functions_info[entry_offset]["instructions"].append(disasm)

                    # Use XrefsFrom to get only call-type references
                    # fl_CN = near call, fl_CF = far call
                    xref = ida_xref.xrefblk_t()
                    ok = xref.first_from(ea, ida_xref.XREF_FAR)
                    while ok:
                        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
                            target_func = ida_funcs.get_func(xref.to)
                            if target_func is not None:
                                target_offset = hex(target_func.start_ea)
                                if target_offset not in seen_targets:
                                    function_call_graph.append(
                                        '  "{}" -> "{}";'.format(
                                            entry_offset, target_offset
                                        )
                                    )
                                    seen_targets.add(target_offset)
                        ok = xref.next_from()

                ea = idc.next_head(ea, func.end_ea)

    function_call_graph.append("}")

    # Write DOT file
    dot_path = os.path.join(output_folder, base_name + ".dot")
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write("\n".join(function_call_graph))

    # Write JSON file
    json_path = os.path.join(output_folder, base_name + ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(functions_info, f, indent=4)


try:
    main()
    ida_pro.qexit(0)
except Exception:
    import traceback
    traceback.print_exc()
    ida_pro.qexit(1)
