# binfold

A utility for quickly (4 seconds on 100MB exe) and accurately porting huge numbers (102520 out of 190396 matched (>50% !!)) of symbols between similar binaries.


<details open>
<summary>Binary Ninja showing ported symbols</summary>
<img alt="An Unreal Engine game showing ported symbols" src="https://github.com/user-attachments/assets/f8c18061-b4f8-41a1-8493-fc6c614fc4ae" />
</details>

## Building

```bash
cargo build --release
```

## Usage

### 1a. Download a pre-generated database

- [Unreal Engine](https://drive.google.com/file/d/18rWfF7MobqxTc8NQzZOoMzZxuxiTUHAv/view)

### 1b. Generate your own

Create a database from executables with PDBs:

```bash
# Single executable
cargo run --release gen-db -e /path/to/binary.exe -d db.fold

# Multiple executables
cargo run --release gen-db -e /path/to/binary1.exe -e /path/to/binary2.exe -d db.fold

# Recursively scan directories for EXE files with PDBs
cargo run --release gen-db -e /path/to/directory -d db.fold
```

### 2. Analyze an executable

Analyze functions in a binary and optionally match against a database:

```bash
# Generate a PDB file with matched function names
cargo run --release analyze --exe /path/to/binary.exe --database db.fold --generate-pdb
```

### 3. Merge databases

Merge multiple database files into a single database:

```bash
# Merge two or more database files
cargo run --release merge-db -d db1.fold -d db2.fold -o merged.fold

# Recursively scan directories for .fold files
cargo run --release merge-db -d /path/to/database/directory -o combined.fold

# Mix files and directories
cargo run --release merge-db -d db1.fold -d /path/to/more/databases -d db3.fold -o all.fold
```

## Matching algorithm

The core matching algorithm is based on [WARP](https://github.com/vector35/warp) which is essentially a hash of function body bytes. However, my implementation has deviated significantly where it comes to constraints. The current implementation populates and matches against the following types of constraints:
- function call bodies (hash of function body)
- function call names (hash of symbol name)
- const string references

Constraints can have an optional offset attached but they are not currently used.

## Future

Some more ideas worth exploring:
- matching and naming global variables (tricky because there is nothing to hash like a function body)
- add constraints based on variable names
- add type information to symbols (like WARP does)
- improve function basic block analysis (notably jump tables)

