# The environment the root-only security proofs actually need (#1748 WU3).
#
# `cargo test` on a normal box cannot be the root gate for this crate:
#
#   * 23 of the lib tests fail when run as root, because they build fixtures under `/tmp` — and `/tmp` is
#     mode 1777, which the whole-chain install-root verify correctly condemns. The tests are right and the
#     verify is right; the FIXTURE LOCATION is wrong.
#   * the one executable proof of the root-exec guard is root-gated, so unprivileged it skips and as root it
#     fails for that same fixture reason. The single most important test in the crate could not pass in the
#     only environment where it runs.
#
# So this image bakes a purpose-made fixture root: `/dig-fixtures`, root-owned, mode 0755, NOT sticky and
# NOT world-writable, on a chain (`/`) that is likewise clean. Tests read `DIG_TEST_FIXTURE_ROOT` and build
# their trees there instead of `/tmp`, which un-skips the guard proof and clears the 23 failures without
# weakening the verify by a single bit.
#
# It also provides an unprivileged `alice` (uid 1001) so the gate can attempt a REAL escalation rather than
# asserting on mode bits.
# Trixie, not bookworm: the released DIG binaries require glibc 2.38/2.39 and bookworm ships 2.36, so a
# bookworm-based gate could not run the very binaries it installs. (The platform floor itself is tracked
# separately — DIG-Network/dig_ecosystem#1741/#1736.)
FROM rust:1-trixie

# `sudo` is what the escalation attempt uses, exactly as a stranger's install does. `jq` reads the
# installer's own `--json` report. `libxdo3`/`libgtk` are absent on purpose: nothing here starts a GUI.
RUN apt-get update \
    && apt-get install -y --no-install-recommends sudo jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The fixture root the root-only tests build in. 0755 and root-owned, so a chain rooted here is clean —
# the property `/tmp` cannot have.
RUN mkdir -p /dig-fixtures \
    && chown 0:0 /dig-fixtures \
    && chmod 0755 /dig-fixtures
ENV DIG_TEST_FIXTURE_ROOT=/dig-fixtures

# The attacker in the escalation attempt: an ordinary unprivileged account, no sudo rights.
RUN useradd --create-home --uid 1001 --shell /bin/bash alice

# `/opt` at the mode a correct distribution ships, so the gate measures DIG's own behaviour rather than a
# permissive base image. (The GitHub runner image ships /opt at 0777; that is the image's defect, and the
# installer deliberately does not re-mode a directory the distribution owns.)
RUN chmod 0755 /opt

WORKDIR /work
