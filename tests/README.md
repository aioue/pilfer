# Pilfer Test Suite

Lightweight DRY tests for pilfer vault file manipulation tool.

## What These Tests Do

The unified test suite checks whole-file vaults, session safety, and inline `encrypt_string`. `TestPilferCLI` runs that matrix by calling `pilfer.cli`. `TestPilferStandalone` smoke-checks `pilfer.py` open/close. `TestCompatibility` decrypts one file both ways and compares the plaintext.

### Key Tests

1. **Hash Consistency** - Ensures unchanged files maintain the same hash after re-encryption
2. **Line Ending Preservation** - Verifies that Unix (`\n`), Windows (`\r\n`), and mixed line endings are preserved during vault operations
3. **Modified File Detection** - Tests that the modified file counter accurately reports changes
4. **Compatibility** - Compares plaintext from `pilfer.cli` with plaintext from `pilfer.py open`

### DRY Architecture

Tests use inheritance to eliminate duplication:
- `PilferTestBase` - shared fixtures for the CLI matrix
- `TestPilferCLI` - runs that matrix by calling `pilfer.cli`
- `TestPilferStandalone` - one subprocess smoke test of `pilfer.py` open/close
- `TestCompatibility` - compares CLI-module plaintext with `pilfer.py` open

## Running Tests

### Run All Tests
```bash
cd pilfer/tests
python run_tests.py
```

### Run Individual Test Classes
```bash
# Test CLI version only
python -m unittest test_pilfer_unified.TestPilferCLI

# Test standalone version only  
python -m unittest test_pilfer_unified.TestPilferStandalone

# Test compatibility between versions
python -m unittest test_pilfer_unified.TestCompatibility
```

### Run Specific Tests
```bash
# Test hash consistency for CLI version
python -m unittest test_pilfer_unified.TestPilferCLI.test_unchanged_files_same_hash

# Test line ending preservation for the CLI matrix
python -m unittest test_pilfer_unified.TestPilferCLI.test_line_endings_preserved
```

## Test Structure

- `test_pilfer_unified.py` - Unified DRY test suite for both versions
- `run_tests.py` - Test runner that executes all test classes and provides a summary

## Expected Output

When all tests pass, you should see:
```
✅ All tests passed! Both pilfer versions work correctly.
   ✓ CLI and standalone versions behave identically
   ✓ Hash consistency maintained for unchanged files
   ✓ Line endings preserved during re-encryption
   ✓ Modified file detection working properly
```

## Requirements

- Python 3.10+
- `ansible` package (for VaultLib)
- Both `pilfer.py` and `pilfer/cli.py` present in the pilfer directory

## Benefits of DRY Architecture

- **Single Source of Truth** - Test logic is defined once in the base class
- **Consistent Testing** - Both versions automatically get the same test coverage
- **Easy Maintenance** - Adding new tests automatically applies to both versions
- **Reduced Duplication** - ~50% reduction in test code while maintaining full coverage 
