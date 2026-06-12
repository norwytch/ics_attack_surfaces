# Security Policy

## Supported versions

This is a research / portfolio project. Security fixes are applied to the latest `main`.

| Version | Supported |
|---------|-----------|
| `main`  | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

Please report security issues **privately** rather than opening a public issue:

- Use GitHub's private vulnerability reporting (repo **Security** tab → *Report a
  vulnerability*), or
- open a minimal issue asking for a private contact channel.

Include a description, reproduction steps, and impact. Expect an acknowledgement within a few
days.

This is a static, model-based analysis tool that processes only local, hand-authored data and
public security feeds, so its realistic attack surface is small — primarily dependency
vulnerabilities and the NVD / MITRE / CISA fetchers. Reports in those areas are especially
welcome.

## Supply-chain hygiene

- Runtime and dev dependencies are pinned in [`requirements.lock`](requirements.lock).
- CI runs [`pip-audit`](https://github.com/pypa/pip-audit) against the lockfile on every push
  and pull request, failing on any known-vulnerable dependency.
- GitHub Actions are pinned by commit SHA, and Dependabot opens update PRs for both Python
  packages and Actions.
