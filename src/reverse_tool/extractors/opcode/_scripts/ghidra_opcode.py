"""Ghidra postScript for opcode extraction.

Runs inside Ghidra's PyGhidra environment (Ghidra 12.0+).
"""
import csv
import os

argv = getScriptArgs()

if len(argv) < 1:
    raise ValueError("Missing argument: CSV output path")

csv_output_path = argv[0]
program = currentProgram
file_name = program.getName()

# Binary metadata
language = program.getLanguage()
processor = language.getProcessor().toString()
addr_size = program.getDefaultPointerSize()
bits = addr_size * 8
is_big_endian = language.isBigEndian()

memory_blocks = program.getMemory().getBlocks()

if not memory_blocks:
    raise Exception(f"{file_name}: No memory blocks found")

all_opcodes = []
index = 0
for block in memory_blocks:
    if not block.isInitialized() or not block.isExecute():
        continue

    section_name = block.getName()
    from ghidra.program.model.address import AddressSet
    address_set = AddressSet(block.getStart(), block.getEnd())

    instructions = program.getListing().getInstructions(address_set, True)
    for instr in instructions:
        addr = int(instr.getAddress().getOffset())
        mnemonic = instr.getMnemonicString()
        instruction_text = str(instr)
        size = instr.getLength()
        # Get raw bytes as hex string
        try:
            raw_bytes = ''.join(f'{b & 0xff:02x}' for b in instr.getBytes())
        except Exception:
            raw_bytes = ''

        all_opcodes.append([index, addr, mnemonic, instruction_text, size, raw_bytes, section_name])
        index += 1

if not all_opcodes:
    raise Exception(f"{file_name}: No instructions found in executable blocks")

output_dir = os.path.dirname(csv_output_path)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)

with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
    csvwriter = csv.writer(csvfile)
    # Metadata row (prefixed with #)
    csvwriter.writerow(["#meta", processor, str(bits), "big" if is_big_endian else "little"])
    # Data header
    csvwriter.writerow(['index', 'addr', 'mnemonic', 'instruction', 'size', 'bytes', 'section'])
    csvwriter.writerows(all_opcodes)
