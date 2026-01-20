# Contributing to Spine

Thank you for your interest in contributing to Spine!

## Development Setup

### Python SDK

```bash
cd spine-sdk-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check .

# Run type checker
mypy spine_client/
```

### Rust CLI

```bash
cd spine-cli

# Build
cargo build

# Run tests
cargo test

# Run clippy (linter)
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Code Style

### Python

- Follow PEP 8
- Use type hints for all public functions
- Run `ruff check .` before committing
- Line length: 100 characters

### Rust

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Document public APIs with doc comments

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Make changes**: Follow the code style guidelines
3. **Add tests**: Cover new functionality with tests
4. **Update docs**: Update README or docs if needed
5. **Run checks**: Ensure all tests and lints pass
6. **Submit PR**: Describe your changes clearly

### PR Title Format

Use conventional commit style:

- `feat: add new verification mode`
- `fix: handle empty WAL files`
- `docs: update installation instructions`
- `test: add chain verification tests`
- `refactor: simplify hash computation`

## Testing

### Python SDK Tests

```bash
cd spine-sdk-python
pytest                        # Run all tests
pytest -v                     # Verbose output
pytest tests/test_wal.py      # Run specific file
pytest -k "test_verify"       # Run tests matching pattern
```

### Rust CLI Tests

```bash
cd spine-cli
cargo test                    # Run all tests
cargo test -- --nocapture     # Show println! output
cargo test verify             # Run tests with "verify" in name
```

## Test Vectors

When modifying hash or signature logic, verify against the test vectors:

```bash
# Test vectors are in test-vectors/vectors.json
# They contain known-good inputs and expected outputs
```

## What We're Looking For

### Good First Issues

- Documentation improvements
- Additional test coverage
- Error message improvements
- Example scripts

### Feature Contributions

Before starting major features, please open an issue to discuss:

- New verification modes
- Additional export formats
- Performance optimizations
- New language SDKs

## Security

If you discover a security vulnerability, please follow our [Security Policy](./SECURITY.md) instead of opening a public issue.

## Questions?

Open a GitHub issue with your question, and we'll respond as quickly as possible.
