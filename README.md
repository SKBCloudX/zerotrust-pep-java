# zerotrust-pep-spring-boot-starter

[![CI](https://github.com/SKBCloudX/zerotrust-pep-java/actions/workflows/ci.yml/badge.svg)](https://github.com/SKBCloudX/zerotrust-pep-java/actions/workflows/ci.yml)

Authorizes every request reaching a Spring Cloud Gateway by asking an external decision
point, and **denies when no decision can be obtained**.

The gateway enforces; it does not decide. Keeping those apart is what lets the decision
point change its policy engine without this library caring, and lets one deployment point
it somewhere else entirely.

```xml
<!-- 1. Standard Maven Central / Repository dependency -->
<dependency>
  <groupId>com.skbroadband</groupId>
  <artifactId>zerotrust-pep-spring-boot-starter</artifactId>
  <version>1.0.0</version>
</dependency>

<!-- 2. Local file system dependency (before Maven Central release) -->
<dependency>
  <groupId>com.skbroadband</groupId>
  <artifactId>zerotrust-pep-spring-boot-starter</artifactId>
  <version>1.0.0</version>
  <scope>system</scope>
  <systemPath>${project.basedir}/lib/zerotrust-pep-spring-boot-starter-1.0.0.jar</systemPath>
</dependency>
```

```yaml
zt:
  pep:
    enabled: true                     # off by default — adding the jar changes nothing
    mode: global                      # or per-route
    decision-url: https://icam.internal/access/v1/evaluation
    jwt-public-key-path: /etc/gw/jwt_pub.pem
    jwt-issuer: https://iam.example.com
    jwt-audience: example-api
```

**No source changes are needed in the host gateway.** Registration happens through Spring
Boot auto-configuration, which is read from every jar on the classpath. (A `@Component`
would not work here — it is only found by the host's own component scan, which does not
cover this library's package.)

## Two shapes, one implementation

| `zt.pep.mode` | Applies to |
|---|---|
| `global` (default) | every route |
| `per-route` | routes that list `- name: ZeroTrustPep` |

Both share the same enforcement logic. They exist as configuration because the two
hand-copied filters this library replaces had drifted into different shapes — ending that
drift is the point.

Prefer `global`. `per-route` leaves unnamed routes unprotected, which is the opposite of
default-deny.

## What it guarantees

- **Fail closed.** No decision — unreachable decision point, non-2xx, unreadable body,
  timeout — means the request is denied. There is no configuration that disables
  enforcement for a route while leaving the filter registered.
- **Denials are always explained.** A denial with no reason produces `UNSPECIFIED` rather
  than an empty audit record.
- **Unknown reason codes still read as denials.** The published vocabulary grows without a
  major version bump, so reason codes are strings, not an enum. Treat anything unfamiliar
  the way you treat `UNSPECIFIED`.

## What it deliberately does not do

**Rate limiting.** The filter this library was extracted from carried an in-memory,
per-instance counter keyed by client address. That is not ported, on purpose:

- it counts per gateway instance, so it does not hold across a scaled-out deployment;
- it resets on restart;
- Spring Cloud Gateway already ships `RequestRateLimiter` with a shared backend.

Shipping a weaker limiter inside an authorization library invites operators to rely on it.
Use the gateway's own limiter and keep this library to enforcement.

**Audit logging.** The original wrote decisions to stdout. A library has no business
choosing an application's log destination or format; decisions surface through the response
and through the decision point's own audit trail, which records the acting subject.

## Compatibility

Every row below is exercised on every push by the [CI matrix](.github/workflows/ci.yml) —
the suite runs against that combination, and the build fails if the versions did not actually
resolve to it.

| Spring Boot | Spring Cloud | Java | |
|---|---|---|---|
| 3.3.x | 2023.0.x | 17, 21 | verified |
| 2.7.x | 2021.0.x | 17 | verified |

| | |
|---|---|
| Minimum Java | **17** — class files target 17 |
| Runtime dependencies | **none** — asserted in CI, not just claimed |

Spring APIs are `provided` scope, so your versions win and nothing here reaches your
classpath. That is deliberate three times over: it keeps this library out of your version
conflicts, adds no transitive supply-chain surface, and leaves [NOTICE](NOTICE) almost empty
for procurement review. CI fails if a runtime dependency ever appears.

### Spring Boot 2.7 — works, with one hard limit

Boot 2 reads `META-INF/spring.factories` rather than the Boot 3 registration file, and both
ship. The full suite passes on Boot 2.7.18 with Spring Cloud 2021.0.9.

**The limit is Java, not Spring.** Class files target Java 17, so a Boot 2 application running
on Java 8 or 11 — still common — cannot load them at all. Boot 2.7 on Java 17 is the only Boot
2 configuration that works, and it is the one CI covers.

Java 17 is a deliberate floor rather than an oversight. Boot 2.x left open-source support in
November 2023, and a security component should not stretch to reach a platform that no longer
receives fixes. Boot 2.7 is covered because the cost was one CI row, not because the platform
is recommended.

### What the tests cover

30 tests, of which 18 start a real Spring Cloud Gateway and drive HTTP through it. CI runs
all of them against each supported Spring combination.

| | Status |
|---|---|
| Filter registers through auto-configuration, and stays absent until enabled | **Tested** |
| Allowed request reaches the backend; denied request does not | **Tested** |
| Authorized subject reaches the backend, and a client cannot forge that header | **Tested** |
| Decision request carries subject, roles, path and method where the policy reads them | **Tested** |
| Deny is enforced and the reason reaches the caller | **Tested** |
| Missing, expired, wrong-issuer, foreign-key and `alg=none` tokens are rejected | **Tested** |
| **Fail closed** — decision point erroring, unparseable or hung | **Tested** |
| Unknown reason code is still read as a denial | **Tested** |
| Per-route mode enforces named routes and leaves unnamed ones open | **Tested** |
| That your policy bundle reads the keys this library sends | **Cannot be tested here** — see below |

Every enforcement test also asserts the backend was not reached. "Denied" and "denied but
proxied anyway" look identical to a caller and are entirely different outcomes.

**One thing these tests cannot establish.** They check the request this library builds; they
cannot know which keys your policy bundle reads. Decision APIs flatten the request into policy
input in ways that are not always obvious — a value sent as `resource.id` may arrive nested
while one sent as an extension property arrives at the top level — so a mapping that looks
right can leave a rule silently unmatched. Pin the pairing with a test on your side that
compares the fields your bundle reads against the keys sent here. That failure mode is
partial, not total: some roles keep working while others are refused, which is far harder to
notice than an outage.

## Licence

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

The licence text is the upstream Apache-2.0 wording, unmodified. Copyright is asserted in
[NOTICE](NOTICE) and in an SPDX header on every source file, so nothing needs to be read out
of the licence itself.

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please do not open a public issue.
Note that **a release published to Maven Central can never be modified or withdrawn**, so
fixes ship as new versions.
