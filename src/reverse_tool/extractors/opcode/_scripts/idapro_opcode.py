"""IDAPython script for opcode extraction.

Runs inside IDA Pro 9.x headless (idat -A -S).
Reads _RT_OUTPUT env var for CSV output path.
"""
import csv
import os
import sys

import ida_auto
import ida_bytes
import ida_ida
import ida_pro
import ida_segment
import ida_ua
import idc
import idautils


def main():
    ida_auto.auto_wait()

    output_path = os.environ.get("_RT_OUTPUT")
    if not output_path:
        print("ERROR: _RT_OUTPUT environment variable not set", file=sys.stderr)
        ida_pro.qexit(1)
        return

    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Binary metadata
    arch = ida_ida.inf_get_procname().strip()
    bits = ida_ida.inf_get_app_bitness()
    is_be = ida_ida.inf_is_be()

    all_opcodes = []
    index = 0

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        # Only executable segments
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue

        seg_name = ida_segment.get_segm_name(seg)

        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            if not idc.is_code(ida_bytes.get_flags(head)):
                continue

            mnemonic = idc.print_insn_mnem(head)
            if not mnemonic:
                continue

            disasm = idc.GetDisasm(head)
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, head)
            size = length if length > 0 else 0

            # Raw bytes as hex string
            raw_bytes = ""
            if size > 0:
                byte_data = ida_bytes.get_bytes(head, size)
                if byte_data:
                    raw_bytes = byte_data.hex()

            all_opcodes.append([
                index, head, mnemonic, disasm, size, raw_bytes, seg_name
            ])
            index += 1

    # Write metadata header as first line comment, then CSV
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Metadata row (prefixed with #)
        writer.writerow(["#meta", arch, str(bits), "big" if is_be else "little"])
        # Data header
        writer.writerow(["index", "addr", "mnemonic", "instruction", "size", "bytes", "section"])
        writer.writerows(all_opcodes)


try:
    main()
    ida_pro.qexit(0)
except Exception:
    import traceback
    traceback.print_exc()
    ida_pro.qexit(1)
