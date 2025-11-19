# Security Policy

## Supported Versions

| Version | Supported | Status |
| ------- | --------- | ------ |
| 1.0.1+ (unreleased) | ✅ Yes | Active development with security fixes |
| 1.0.0 | ⚠️ Limited | Original version - upgrade recommended |
| < 1.0.0 | ❌ No | Not supported |

**Recommendation**: Use the latest code from the modernization branches which include critical security fixes.

## Reporting a Vulnerability

**DO NOT** open a public issue for security vulnerabilities.

**Report via**: GitHub private vulnerability reporting
- Navigate to: https://github.com/benschumacher/nss_tacplus/security/advisories
- Click "Report a vulnerability"

**Include**:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response Timeline**:
- Initial Response: Within 48 hours
- Status Update: Within 7 days
- Fix Timeline: 7-60 days depending on severity

## Security Fixes in Modernization

### Fixed Vulnerabilities

✅ **Logic Error in Attribute Normalization** (Medium)
- **Issue**: _normalize_name() always called toupper() even after dash replacement
- **Impact**: Attribute names not properly normalized (e.g., "home-dir" → "HOME_IR")
- **Fix**: Added else clause (src/nss_tacplus.c:417)

✅ **Variable Length Array Stack Overflow** (High)
- **Issue**: VLA sized by untrusted TACACS+ response
- **Impact**: Stack overflow via malicious server
- **Fix**: Replaced with fixed 256-byte buffer + validation

✅ **Memory Leak in Config Reload** (Low)
- **Issue**: freeaddrinfo() never called on config reload
- **Impact**: Memory leak over time
- **Fix**: Added proper cleanup in _check_config()

✅ **Incomplete Config Reload** (Low)
- **Issue**: _check_config() detected changes but didn't reload
- **Impact**: Configuration changes ignored
- **Fix**: Implemented complete reload logic

### Current Security Considerations

⚠️ **Plaintext Secrets in Configuration**
- **Mitigation**: `chmod 600 /etc/tacplus.conf`, `chown root:root`
- **Future**: Consider secret management integration

⚠️ **No Certificate Validation**
- **Note**: TACACS+ protocol limitation, not implementation issue
- **Mitigation**: Use trusted network infrastructure

⚠️ **Syslog May Contain Sensitive Info**
- **Mitigation**: Secure syslog configuration, restrict log access

## Security Best Practices

### Configuration File Security

```bash
# Secure the configuration file
sudo chown root:root /etc/tacplus.conf
sudo chmod 600 /etc/tacplus.conf
```

### Defense in Depth

1. **Network Security**: Isolate TACACS+ servers on trusted network
2. **Access Control**: Limit who can modify NSS configuration
3. **Monitoring**: Monitor authentication logs for anomalies
4. **Updates**: Keep nss_tacplus and pam_tacplus up to date

### Deployment Checklist

- [ ] TACACS+ servers on trusted network segment
- [ ] Firewall rules restrict TACACS+ port (49/tcp)
- [ ] `/etc/tacplus.conf` has mode 0600, owner root
- [ ] Strong secrets (20+ random characters)
- [ ] Syslog configured securely
- [ ] SELinux/AppArmor policies reviewed
- [ ] Monitoring for failed authentication attempts

## Hardening Features

### Compile-Time (Enabled by Default)

- `-D_FORTIFY_SOURCE=2` - Buffer overflow detection
- `-fstack-protector-strong` - Stack smashing protection
- `-fstack-clash-protection` - Stack clash protection
- `-Wl,-z,relro` - Read-only relocations
- `-Wl,-z,now` - Immediate binding (GOT hardening)

### Development Build with Sanitizers

```bash
# CMake with sanitizers (DO NOT use in production)
cmake .. -DENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
make
```

This enables AddressSanitizer and UndefinedBehaviorSanitizer for finding bugs.

## Security Roadmap

- **Phase 1**: Code modularization (clearer security boundaries)
- **Phase 2**: Enhanced validation, rate limiting
- **Phase 3**: Professional audit, fuzzing, penetration testing

---

**Last Updated**: 2024-11-18
