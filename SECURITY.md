# Security Policy

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.0.1+ (unreleased) | ✅ Yes | Active development with security fixes |
| 1.0.0   | ⚠️ Limited | Original version - upgrade recommended |
| < 1.0.0 | ❌ No | Not supported |

**Recommendation**: Use the latest unreleased version from the `master` branch which includes critical security fixes from Phase 0.

## Reporting a Vulnerability

We take security issues seriously. If you discover a security vulnerability, please follow these steps:

### 1. **DO NOT** Open a Public Issue

Security vulnerabilities should not be disclosed publicly until a fix is available.

### 2. Contact Method

**Email**: Report vulnerabilities to the repository owner via GitHub private vulnerability reporting:
- Navigate to: https://github.com/benschumacher/nss_tacplus/security/advisories
- Click "Report a vulnerability"

Alternatively, open a draft security advisory.

### 3. Information to Include

Please provide:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information (for follow-up)

### 4. Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: Best effort

### 5. Disclosure Policy

- Coordinated disclosure preferred
- Public disclosure after fix is available
- Credit given to reporter (unless anonymity requested)

## Known Security Considerations

### Fixed in Phase 0 (Unreleased)

✅ **CVE-TBD-001: Logic Error in Attribute Normalization**
- **Severity**: Medium
- **Issue**: _normalize_name() always called toupper() even after dash replacement
- **Impact**: Attribute names not properly normalized
- **Fix**: Added else clause in src/nss_tacplus.c:417
- **Status**: Fixed in unreleased version

✅ **CVE-TBD-002: Variable Length Array Stack Overflow**
- **Severity**: High
- **Issue**: VLA sized by untrusted TACACS+ response (attr->attr_len)
- **Impact**: Stack overflow via malicious TACACS+ server
- **Fix**: Replaced with fixed-size buffer (MAX_ATTR_NAME_LEN) and bounds checking
- **Status**: Fixed in unreleased version

✅ **CVE-TBD-003: Memory Leak in Configuration Reload**
- **Severity**: Low
- **Issue**: freeaddrinfo() never called on config reload
- **Impact**: Memory leak over time
- **Fix**: Added proper cleanup in _check_config()
- **Status**: Fixed in unreleased version

✅ **CVE-TBD-004: Incomplete Configuration Reload**
- **Severity**: Low
- **Issue**: _check_config() detected changes but didn't reload
- **Impact**: Configuration changes ignored
- **Fix**: Implemented complete reload logic
- **Status**: Fixed in unreleased version

### Current Considerations (Design Limitations)

⚠️ **Plaintext Secrets in Configuration**
- **Issue**: /etc/tacplus.conf stores TACACS+ secrets in plaintext
- **Mitigation**:
  - Set file permissions: `chmod 600 /etc/tacplus.conf`
  - Owned by root: `chown root:root /etc/tacplus.conf`
  - Consider encrypted filesystem
- **Future**: Investigate secret management integration (Phase 3)

⚠️ **No Certificate Validation for TACACS+ Servers**
- **Issue**: TACACS+ protocol uses shared secret, not PKI
- **Mitigation**: Use trusted network infrastructure
- **Note**: This is a protocol limitation, not implementation bug

⚠️ **Syslog May Contain Sensitive Information**
- **Issue**: Debug logs may contain usernames, server IPs
- **Mitigation**:
  - Secure syslog configuration
  - Restrict access to log files
  - Set appropriate debug-level in config

⚠️ **No Rate Limiting**
- **Issue**: No protection against brute force
- **Mitigation**: Rely on TACACS+ server rate limiting
- **Future**: Consider client-side rate limiting (Phase 2)

## Security Best Practices

### Configuration File Security

```bash
# Secure the configuration file
sudo chown root:root /etc/tacplus.conf
sudo chmod 600 /etc/tacplus.conf

# Verify permissions
ls -la /etc/tacplus.conf
# Should show: -rw------- 1 root root
```

### Minimal Configuration Example

```
# /etc/tacplus.conf - Minimal secure configuration
server 192.168.1.10
secret <use-strong-secret-here>
timeout 5
service linuxlogin
protocol ssh
```

### Defense in Depth

1. **Network Security**: Isolate TACACS+ servers on trusted network
2. **Access Control**: Limit who can modify NSS configuration
3. **Monitoring**: Monitor authentication logs for anomalies
4. **Updates**: Keep nss_tacplus and pam_tacplus up to date
5. **Testing**: Test configuration changes in staging first

### Secure Deployment Checklist

- [ ] TACACS+ servers on trusted network segment
- [ ] Firewall rules restrict TACACS+ port (49/tcp) access
- [ ] `/etc/tacplus.conf` has mode 0600, owner root
- [ ] Strong secrets used (20+ random characters)
- [ ] Syslog configured to secure log server
- [ ] SELinux/AppArmor policies reviewed
- [ ] Regular security updates applied
- [ ] Monitoring for failed authentication attempts

## Hardening Features

### Compile-Time (Enabled by Default)

- `-D_FORTIFY_SOURCE=2` - Buffer overflow detection
- `-fstack-protector-strong` - Stack smashing protection
- `-fstack-clash-protection` - Stack clash protection
- `-Wl,-z,relro` - Read-only relocations
- `-Wl,-z,now` - Immediate binding (GOT hardening)

### Build with Extra Hardening

```bash
# CMake build with sanitizers (development only)
cmake .. -DENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
make

# This enables:
# - AddressSanitizer (ASan) - memory errors
# - UndefinedBehaviorSanitizer (UBSan) - undefined behavior
```

**Warning**: Do not deploy sanitizer builds to production (performance impact).

## Security Roadmap

### Phase 1: Modularization (Planned)
- Reduce attack surface through code organization
- Clearer security boundaries between modules

### Phase 2: Feature Enhancement (Planned)
- Client-side rate limiting
- Enhanced input validation
- Audit logging improvements

### Phase 3: Production Readening (Planned)
- Professional security audit
- Fuzzing of config parser
- Fuzzing of TACACS+ response parser
- Penetration testing

## Historical Vulnerabilities

None publicly disclosed at this time.

## Security Contacts

- **Primary**: Repository owner via GitHub
- **Security Advisories**: https://github.com/benschumacher/nss_tacplus/security/advisories

## Additional Resources

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE: Common Weakness Enumeration](https://cwe.mitre.org/)
- [TACACS+ Protocol RFC](https://datatracker.ietf.org/doc/html/rfc8907)

---

**Last Updated**: 2024-11-18
**Version**: Phase 0 (Unreleased)
