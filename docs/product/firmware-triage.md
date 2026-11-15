# Firmware analysis

The `firmware` plugin performs triage with a bounded disassembler. It never decompiles
and never executes the image.

## 1. Pipeline

```
firmware bytes
  1. container detection: ELF magic, Intel HEX, raw
  2. statistics: block entropy, byte histogram, ASCII and UTF-16LE strings
  3. structural hints: the first sixteen words as a Cortex-M vector table, alignment,
     pointer density
  4. bounded Thumb disassembly when steps 1-3 make it plausible
```

## 2. Architecture support

The decoder targets ARMv7-M Thumb.

| Item | Behaviour |
|---|---|
| Thumb-16 | Structural decode across all groups: shifts, ALU, load/store, push/pop, branches, SVC, UDF, misc |
| Selected 32-bit encodings | `BL`, `MOVW`, `MOVT`, literal `LDR` |
| Length sync | Every Thumb and Thumb-2 encoding yields a length and the walk continues; valid but unmodelled encodings are named after their group (`thumb2.other`, `misc16`) and are not counted as unknown |
| Function starts | Vector-table entries plus `BL` targets, deduplicated and capped |
| Not implemented | Decompilation to C, type recovery, non-ARM architectures |

Decode coverage is defined as
`decode_coverage_x100 = (instructions - unknown) / instructions * 100`, where `unknown`
counts only bytes whose encoding could not be determined. A value of 100 therefore means
the length walk completed; it does not mean every mnemonic is modelled. Coverage below
95% adds a `warning` finding.

## 3. Output fields

| Field | Meaning |
|---|---|
| `kind` | `elf`, `intel-hex` or `raw` |
| `size`, `base_address`, `architecture` | Input identity as analysed |
| `entropy_blocks`, `entropy_block_size`, `entropy_mean_x100`, `entropy_max_x100`, `entropy_max_offset`, `high_entropy_blocks` | Block entropy profile (1024-byte blocks, values scaled by 100) |
| `ascii_strings`, `ascii_string_bytes`, `utf16_runs`, `utf16_chars`, `strings_sample_N` | String inventory and previews |
| `vector_table_valid`, `entry_point`, `initial_sp`, `thumb_entry`, `sp_plausible` | Cortex-M vector-table heuristic |
| `disassembly_arch` | `thumb` when decoding ran, otherwise `none` |
| `instructions`, `unknown_opcodes`, `decode_coverage_x100` | Decode volume and quality |
| `functions`, `function_1`..`function_3` | Detected function starts |
| `insn_1`..`insn_4` | `0xADDRESS: mnemonic operands` samples from the first decoded instruction onward |
| `literal_refs`, `strings_referenced`, `pointer_refs`, `xref_1`..`xref_4` | Literal references, referenced strings, and how many of those went through a pointer word |

Findings follow the shared conventions: `info` states an observation (high-entropy
region), `warning` states suspicion (a raw image without a valid vector table, decode
coverage below 95%). The plugin never emits a severity above `warning`, because triage is
not a security rating.

## 4. Literal-pool cross references

ARM compilers load data addresses in two shapes, and the decoder follows both:

| Shape | Instruction | What is recorded |
|---|---|---|
| Address formed directly | `ADR`, `MOVW`+`MOVT` | the address itself |
| Address in a literal slot | `LDR Rt, [pc, #imm]` | the slot address and the pointer word read from it |

The second shape is the usual "string pointer table": the PC-relative load reads a word
that points at the string. Comparing only the slot address with the string address would
miss it, so the decoder dereferences the slot when the word lies inside the image and
counts those hits as `pointer_refs`. A slot outside the image, or one whose word would
cross the image end, yields no pointer (null) rather than a guess.

```
analyze --protocol firmware --base 0x08000000 --arch thumb f3-demo.bin
  literal_refs: 2     strings_referenced: 2     pointer_refs: 1
  xref_1: "PocketRoot-F3" <- 0x08000100 slot 0x08000104 -> 0x08000120 in 0x08000100 [literal-load]
  xref_2: "DirectRef" <- 0x08000008 in 0x08000008
```

The `[literal-load]` marker means the string was reached through the pointer word; the
line names the loading instruction, the slot, the pointer and the containing function.

### MOVW/MOVT pairs

Position-independent code builds 32-bit addresses from `movw rX, #lo16` and
`movt rX, #hi16`. The decoder records both immediates and pairs them per register within
a window of four instructions, producing `(hi << 16) | lo`. Paired references are marked
`[movw/movt]`.

```
literal_refs: 2     strings_referenced: 2
xref_1: "DirectRef" <- 0x08000008 in 0x08000008
xref_2: "PairRef" <- 0x0800000a in 0x08000008 [movw/movt]
```

The window is a heuristic: a write to the same register between the two instructions can
still produce a wrong pair, which is why the technique marker is part of the output. The
containing function is the nearest function entry at or below the instruction address; it
is a static inference, not symbol-table data.

### Tests

```
analyze --protocol firmware --base 0x08000000 --arch thumb thumb-demo.bin
  instructions: 43   unknown_opcodes: 0   decode_coverage_x100: 100   functions: 2
  insn_1: 0x08000008: movs r0, #0x1
  insn_3: 0x0800000c: bl #0x08000020
```

## 5. Parameters

Firmware analysis needs a load address and an architecture, which the parameter-free
plugin entry point cannot express. The descriptor therefore also accepts an options
struct:

```zig
pub const AnalyzeOptions = struct { architecture: ?[]const u8 = null, base_address: u32 = 0 };
```

`analyze` remains mandatory and is used when no options are supplied; `analyze_with`
receives them. The CLI exposes `--base <hex>` and `--arch <thumb|arm|cortex-m|none>`;
`--arch none` disables disassembly and leaves the triage fields.

## 6. Limits

| Limit | Value |
|---|---|
| Decoded instructions per analysis | 65536 |
| Detected functions | 64 |
| Instruction samples in the result | 8 |
| Literal references | 4096 |
| String references scanned | 64 |
| Cross-reference lines in the result | 4 |
| Entropy block size | 1024 bytes |
| String previews | 8 (48 bytes each) |
| MOVW/MOVT pairing window | 4 instructions |
