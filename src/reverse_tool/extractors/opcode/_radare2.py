"""Radare2-specific opcode extraction logic."""

from __future__ import annotations

import logging
from typing import Any


def extract_opcodes_radare2(
    session: Any,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Extract opcodes using Radare2 via r2pipe.

    Returns dict with 'opcodes' (from executable sections) and 'sections' (all).
    """
    file_name = session.input_file.name
    r2 = session.r2

    r2.cmd("aa")  # Basic analysis — sufficient for opcode extraction
    r2.cmd("e asm.flags.middle=0")

    sections = r2.cmdj("iSj")
    if not sections:
        logger.error("%s: No sections found", file_name)
        return {"opcodes": [], "sections": []}

    # Section metadata
    section_info = [
        {
            "name": s["name"],
            "size": s["size"],
            "vaddr": s["vaddr"],
            "paddr": s["paddr"],
            "perm": s.get("perm", ""),
            "type": s.get("type", ""),
        }
        for s in sections
        if s["size"] > 0
    ]

    # Extract file info
    file_info = r2.cmdj("ij") or {}
    bin_info = file_info.get("bin", {})

    # Skip non-executable sections (data bytes produce invalid instructions)
    all_opcodes: list[dict[str, Any]] = []
    index = 0
    for section in sections:
        if section["size"] <= 0:
            continue
        if "x" not in section.get("perm", ""):
            continue

        instructions = r2.cmdj(f"pDj {section['size']} @{section['vaddr']}") or []
        for instr in instructions:
            opcode_full = instr.get("opcode", "")
            if not opcode_full or opcode_full == "invalid":
                continue
            addr = instr.get("addr")
            if addr is None:
                continue

            parts = opcode_full.split(None, 1)
            mnemonic = parts[0] if parts else opcode_full

            all_opcodes.append(
                {
                    "index": index,
                    "addr": addr,
                    "mnemonic": mnemonic,
                    "instruction": opcode_full,
                    "size": instr.get("size", 0),
                    "bytes": instr.get("bytes", ""),
                    "type": instr.get("type", ""),
                    "section": section["name"],
                }
            )
            index += 1

    return {
        "opcodes": all_opcodes,
        "sections": section_info,
        "binary_info": {
            "arch": bin_info.get("arch", ""),
            "bits": bin_info.get("bits", 0),
            "format": bin_info.get("bintype", ""),
            "os": bin_info.get("os", ""),
            "endian": bin_info.get("endian", ""),
        },
    }
