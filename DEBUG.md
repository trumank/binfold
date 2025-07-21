# WARP Debug Commands

The WARP tool includes comprehensive debug commands for analyzing functions, basic blocks, and GUID calculations.

## Debug Command Usage

```bash
cargo run -- debug --file <PE_FILE> --address <HEX_ADDRESS> --debug <FLAGS>
```

### Debug Flags

- `size` - Shows detailed function size analysis including:
  - Scan range and limits
  - Number of decoded instructions
  - Recursive descent analysis
  - Final computed size
  
- `blocks` - Shows basic block analysis including:
  - Number of decoded instructions
  - Reachable instruction count
  - Block boundaries
  - Full disassembly of each basic block
  
- `instructions` - Shows first 50 decoded instructions with:
  - Address
  - Assembly code
  - Flow control type
  
- `guid` - Shows GUID calculation details including:
  - Individual block GUIDs
  - Instruction processing (KEEP/SKIP/ZERO)
  - Final function GUID calculation
  
- `all` - Enables all debug flags

### Examples

#### Debug function size calculation
```bash
cargo run -- debug --file main.exe --address 0x140001bf4 --debug size
```

#### Debug basic block identification
```bash
cargo run -- debug --file main.exe --address 0x140001bf4 --debug blocks
```

#### Debug GUID calculation
```bash
cargo run -- debug --file main.exe --address 0x140001bf4 --debug guid
```

#### Full debug output
```bash
cargo run -- debug --file main.exe --address 0x140001bf4 --debug all
```

#### Multiple debug flags
```bash
cargo run -- debug --file main.exe --address 0x140001bf4 --debug size --debug blocks
```

### Understanding the Output

#### Size Analysis
- Shows the recursive descent algorithm tracking control flow
- Reports visited vs total decoded instructions
- Identifies function boundaries

#### Block Analysis
- Lists all basic blocks with start/end addresses
- Shows block count and reachability
- Provides full disassembly for each block

#### GUID Analysis
- Shows how each instruction contributes to the GUID
- KEEP: Instruction bytes included as-is
- ZERO RELOC: Relocatable instructions zeroed out
- SKIP REG2REG: Register-to-self moves skipped
- Shows final UUID calculation with namespace

### Troubleshooting Functions

Use these debug commands to:
1. Verify correct function size detection
2. Check basic block boundaries match expectations
3. Understand why GUIDs might differ from other tools
4. Debug instruction classification for GUID calculation

### Performance Notes

- The instruction decoder has a 2000 instruction limit for safety
- Large functions (>64KB) may hit scan limits
- Debug output can be verbose - consider redirecting to a file for analysis