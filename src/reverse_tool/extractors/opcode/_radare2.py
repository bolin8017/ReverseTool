"""Radare2-specific opcode extraction logic."""

from __future__ import annotations

import logging
from typing import Any


def extract_opcodes_radare2(
    session: Any,  # Radare2Session
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    """Extract opcodes using Radare2 via r2pipe.

    Iterates all sections, disassembles each, and collects opcode mnemonics.
    """
    file_name = session.input_file.name
    r2 = session.r2

    try:
        r2.cmd("e asm.flags.middle=0")
        sections = r2.cmdj("iSj")

        if not sections:
            logger.error(
                "%s: No sections found — file may be packed or damaged",
                file_name,
            )
            return []

        all_opcodes: list[dict[str, Any]] = []
        for section in sections:
            if section["size"] <= 0:
                continue
            instructions = r2.cmdj(f"pDj {section['size']} @{section['vaddr']}") or []
            for instr in instructions:
                opcode = instr.get("opcode", "")
                addr = instr.get("offset", instr.get("addr"))
                if opcode and addr is not None:
                    all_opcodes.append(
                        {
                            "addr": addr,
                            "opcode": opcode.split()[0],
                            "section_name": section["name"],
                        }
                    )

        return all_opcodes

    except Exception as e:
        logger.exception("%s: Unexpected error: %s", file_name, e)
        return []
