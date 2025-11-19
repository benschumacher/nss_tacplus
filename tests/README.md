# nss_tacplus Test Suite

## Overview

This directory contains tests for the nss_tacplus module.

## Current Status

Phase 0 establishes the test infrastructure. Actual test implementations will be added in later phases.

## Test Structure (Planned)

```
tests/
├── README.md           # This file
├── test_config.c       # Configuration parsing tests (TODO)
├── test_passwd.c       # passwd struct building tests (TODO)
├── test_integration.c  # Integration tests (TODO)
└── mock_tacplus.py     # Mock TACACS+ server (TODO)
```

## Running Tests

### Using CMake

```bash
mkdir build && cd build
cmake .. -DBUILD_TESTING=ON
make
ctest
```

### Using Make

```bash
make test
./bin/dlharness ./libnss_tacplus.so.2 _nss_tacplus_getpwnam_r testuser
```

## Test Requirements

- cmocka (for unit tests)
- Python 3 (for mock TACACS+ server)
- Root access may be required for some integration tests

## Planned Tests

- [ ] Unit tests for configuration parsing
- [ ] Unit tests for attribute normalization
- [ ] Unit tests for passwd struct population
- [ ] Integration tests with mock TACACS+ server
- [ ] Fuzzing tests for config parser
- [ ] Fuzzing tests for TACACS+ response parser
- [ ] Performance benchmarks

## Contributing

See CONTRIBUTING.md for guidelines on adding new tests (to be created).
