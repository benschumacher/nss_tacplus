# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Modern CMake build system (CMakeLists.txt) with comprehensive configuration
- GitHub Actions CI/CD pipeline for automated testing
- Test infrastructure directory (tests/)
- Security hardening compiler flags (-fstack-protector-strong, -fstack-clash-protection)
- Memory safety improvements with bounds checking
- Input validation for TACACS+ attribute lengths (MAX_ATTR_NAME_LEN)
- Complete implementation of configuration hot-reload in _check_config()
- Proper memory management with freeaddrinfo() to prevent leaks
- Install target in Makefile
- CHANGELOG.md (this file)
- SECURITY.md with security policy

### Changed
- Improved Makefile with hardening flags and install target
- Enhanced compiler flags: -O2, -Wall, -Wextra, -Wl,-z,relro, -Wl,-z,now
- Configuration reload now properly frees old server list
- Updated CFLAGS to use /usr/local/include instead of /usr/local/lib

### Fixed
- **CRITICAL**: Fixed logic error in _normalize_name() where toupper() was always
  called even after replacing '-' with '_' (src/nss_tacplus.c:417)
- **SECURITY**: Replaced Variable Length Array (VLA) with fixed-size buffer to
  prevent stack overflow attacks (src/nss_tacplus.c:504)
- **MEMORY LEAK**: Added freeaddrinfo() call in _check_config() to prevent leak
  during configuration reload
- **INCOMPLETE**: Completed _check_config() implementation that was previously
  just a comment
- Fixed Makefile typo: (OBJECTS) -> $(OBJECTS) in .PRECIOUS target

### Security
- Added bounds checking for attribute name lengths
- Replaced unsafe VLA with MAX_ATTR_NAME_LEN constant (256 bytes)
- Added validation to skip overly long attribute names
- Implemented complete config reload to prevent use-after-free
- Added security hardening linker flags (RELRO, NOW binding)

## [1.0.0] - 2015-09-19

### Added
- Initial release of nss_tacplus module
- NSS integration for TACACS+ authentication
- Configuration file support (/etc/tacplus.conf)
- Support for multiple TACACS+ servers
- Basic attribute mapping (uid, gid, home, shell)
- Test harness (dlharness) for manual testing
- Example PAM configuration
- RPM spec file

### Notes
This version was the last commit before the modernization effort began.

---

## Migration Guide

### From 1.0.0 to Unreleased

**No breaking changes** - All configuration files remain compatible.

**New build options:**

```bash
# Traditional Make (still supported)
make
make install

# Modern CMake (recommended)
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_HARDENING=ON
make
sudo make install
```

**Security improvements:**
- No action required, but existing deployments benefit from:
  - Fixed critical bugs automatically
  - Improved memory safety
  - Configuration hot-reload now works correctly

**Testing:**
After upgrading, verify with:
```bash
./bin/dlharness ./libnss_tacplus.so.2 _nss_tacplus_getpwnam_r <username>
```

---

## Phase 0 Completion: Critical Fixes & Foundation ✅

This release completes **Phase 0** of the modernization plan:

- ✅ All critical security bugs fixed
- ✅ Modern build system (CMake + improved Makefile)
- ✅ CI/CD pipeline established
- ✅ Test infrastructure created
- ✅ Memory leaks addressed
- ✅ Security hardening enabled

**Next Phase**: Code modularization and restructuring (see refactor plan)

---

## Credits

**Original Author**: Ben Schumacher (@benschumacher)

**Phase 0 Modernization**:
- Critical bug fixes and security hardening
- Build system modernization
- CI/CD infrastructure

**Inspired by PR #6**: Kevin Nelson (@kevinnelson-affirmed)
- Per-server secrets concept (to be implemented in Phase 2)
- Default configuration values concept (to be implemented in Phase 2)

---

## Links

- [GitHub Repository](https://github.com/benschumacher/nss_tacplus)
- [Issue Tracker](https://github.com/benschumacher/nss_tacplus/issues)
- [Security Policy](SECURITY.md)
- [Refactor Plan](docs/REFACTOR_PLAN.md) *(if created)*
