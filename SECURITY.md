# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | ✅ Active          |
| 0.2.x   | ⚠️ Security fixes only |
| < 0.2   | ❌ Not supported   |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in pipguard, please report it responsibly:

1. **Email**: Send details to [xianpeng.shen@gmail.com](mailto:xianpeng.shen@gmail.com)
2. **GitHub Private Vulnerability Reporting**: Use [GitHub's security advisory feature](https://github.com/shenxianpeng/pipguard/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity
  - CRITICAL: Patch release within 72 hours
  - HIGH: Patch release within 1 week
  - MEDIUM/LOW: Next regular release

## Scope

The following are in scope for security reports:

- **Scanner bypass**: Techniques that allow malicious code to evade pipguard's detection
- **TOCTOU vulnerabilities**: Race conditions between scan and install
- **Allowlist bypass**: Ways to get a malicious package treated as allowlisted
- **Sandbox escape**: Methods to bypass the runtime capability sandbox
- **Code execution in pipguard itself**: Vulnerabilities in pipguard's own code

## Out of Scope

- Vulnerabilities in packages that pipguard scans (report those to the package maintainer or PyPI)
- Social engineering attacks (e.g., convincing a user to use `--force`)
- Issues requiring physical access to the machine

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter notifies us privately
2. We acknowledge and begin working on a fix
3. We release the fix and publish a security advisory
4. Reporter may publish details after the fix is available

We credit reporters in the security advisory unless they prefer to remain anonymous.
