# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities to the maintainers at the address published on the
repository's organization page. **Do not open a public issue for a suspected
vulnerability.**

Please include the affected version, a description of the issue, and reproduction
steps if you have them. We acknowledge reports within 5 business days.

## Supported versions

Fixes are published as new versions. **Artifacts on Maven Central cannot be modified
or withdrawn once published**, so a vulnerable release stays reachable forever — always
upgrade rather than expecting a release to disappear.

| Version | Supported |
|---|---|
| 1.x | Yes |

## Design notes relevant to security

This library authorizes requests by asking an external decision point. Two properties
are intentional and should not be "fixed" without understanding them:

- **Fail closed.** When no decision can be obtained — the decision point is unreachable,
  returns a non-2xx status, or returns an unparseable body — the request is **denied**.
  Allowing it would make the enforcement point pointless.
- **No bypass switch.** There is no configuration that turns enforcement off for a route
  while leaving the filter registered. Disable the whole library (`zt.pep.enabled=false`)
  if you do not want enforcement.

Configuration and the full rationale are in the [README](README.md).

The library carries **no third-party runtime dependencies**. It uses only what the host
Spring application already provides, so it adds no transitive supply-chain surface.
