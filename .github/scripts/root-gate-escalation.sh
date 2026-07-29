#!/usr/bin/env bash
# An EXECUTED privilege-escalation attempt against a real install, run inside the root gate container.
#
# Why this exists (#1748 WU3): every previous round of this release was verified by asserting on mode bits
# and verdict fields, and every round the security leg found another path to `uid=0(root)` that those
# assertions could not see. A gate that measures permissions measures what we already believe. This one
# ATTACKS: an unprivileged account plants a binary where root would run it, root then performs an ordinary
# install, and the gate fails if root ever executed the planted code.
#
# Each attempt carries a FALSIFYING CONTROL — the same attempt with the unsafe posture repaired must
# SUCCEED — so a gate that simply refuses everything cannot pass.
set -euo pipefail

INSTALLER="${INSTALLER:?set INSTALLER to the built dig-installer}"
ATTACKER="${ATTACKER:-alice}"
# The marker the planted binary prints. If this ever appears in root's output, root ran attacker code.
MARKER="DIG-ESCALATION-MARKER"
CLI_ONLY=(--no-dig-node --no-dig-dns --no-auto-update --no-dig-app)

fail() { echo "GATE FAILED: $*" >&2; exit 1; }
note() { printf '\n=== %s\n' "$*"; }

plant_as_attacker() {
  # A binary that reports the uid it runs as, plus a fake version high enough that a version probe which
  # TRUSTS it would decide "already up to date" and skip the download — G1's amplifier.
  local target="$1"
  sudo -u "$ATTACKER" tee "$target" >/dev/null <<PLANTED
#!/bin/sh
echo "$MARKER \$(id)"
echo "digstore 99.0.0"
exit 0
PLANTED
  sudo -u "$ATTACKER" chmod 0755 "$target"
}

note "Baseline: a clean install must SUCCEED (the falsifying control for everything below)"
"$INSTALLER" "${CLI_ONLY[@]}" --json > baseline.json
jq -e '.ok == true'            baseline.json || fail "a clean install must succeed, or every refusal below proves nothing"
jq -e '.result.ready == true'  baseline.json || fail "a clean install must be ready"
test -x /opt/dig/bin/digs      || fail "the baseline install placed no binary"
test -L /usr/local/bin/digs    || fail "the baseline install planted no veneer link"

note "ATTEMPT 1 (G1): the attacker owns the veneer, replaces the link, and waits for the next install"
# The documented Homebrew-on-Intel posture: /usr/local/bin owned by a non-root account, group-writable.
chown "$ATTACKER:$ATTACKER" /usr/local/bin
chmod 0775 /usr/local/bin
sudo -u "$ATTACKER" rm -f /usr/local/bin/digs
plant_as_attacker /usr/local/bin/digs

set +e
"$INSTALLER" "${CLI_ONLY[@]}" --json > attempt1.json 2> attempt1.err
RC=$?
set -e
cat attempt1.err
echo "installer exit: $RC"

# `if !grep`, never `grep && fail`: under `set -e` a non-matching `grep -q` returns 1 and the
# `cmd && fail` compound then exits the script with the attempt LOOKING like it passed. That is the same
# shape as the `grep -q` SIGPIPE trap fixed in the e2e workflow, and it silently skipped every attempt
# after the first until it was caught here.
if grep -q "$MARKER" attempt1.json attempt1.err; then
  fail "root EXECUTED the attacker's binary (G1)"
fi
if grep -q 'uid=0(root)' attempt1.json attempt1.err; then
  fail "root EXECUTED the attacker's binary (G1)"
fi
# The FALLBACK, asserted on what the installer controls.
#
# It must NOT plant a DIG symlink into a directory an unprivileged account owns — that is the vector, and it
# is the one thing here that is entirely ours to decide.
if [ -L /usr/local/bin/digs ] && readlink /usr/local/bin/digs | grep -q '^/opt/dig/bin/'; then
  fail "a DIG link was planted in an attacker-owned veneer - she re-points it and root runs her binary (G1)"
fi
# It must report NOT READY, because her file still SHADOWS the install on PATH and we deliberately do not
# delete it: a regular file in /usr/local/bin may be another package manager's, and vandalising a shared
# system directory is not this installer's to do. So the operator has to be told, precisely.
jq -e '.result.ready == false' attempt1.json   || fail "an install shadowed by a file in an unsafe veneer reported READY, so nothing tells the operator"
jq -r '.result.failures[]' attempt1.json > a1-failures.txt
grep -qi 'shadow' a1-failures.txt   || fail "the failure must name the SHADOWING, which is what an operator has to repair: $(cat a1-failures.txt)"
# And it must have chosen the fallback mechanism rather than the veneer.
jq -e '.result.reachability == "direct_path_entry"' attempt1.json   || fail "an unsafe veneer must fall back to putting the protected root on PATH directly"
# The escalation itself never completed: root did not run her code, which the marker checks above prove.
echo "fallback verified: no DIG link planted, mechanism=direct_path_entry, install reported NOT ready"

note "CONTROL 1: repair ONLY the veneer's ownership and the same install must succeed"
chown 0:0 /usr/local/bin
chmod 0755 /usr/local/bin
rm -f /usr/local/bin/digs
"$INSTALLER" "${CLI_ONLY[@]}" --json > control1.json
jq -e '.ok == true'           control1.json || fail "the refusal was not about the posture - it refuses regardless, so ATTEMPT 1 proves nothing"
jq -e '.result.ready == true' control1.json || fail "the repaired install must be ready"
# The OTHER half of the fallback, and the reason ATTEMPT 1 proves something: with the veneer safe, the link
# IS planted and the veneer IS the mechanism. Without this, an installer that had simply stopped using the
# veneer altogether would satisfy ATTEMPT 1 just as well.
jq -e '.result.reachability == "veneer_links"' control1.json   || fail "a SAFE veneer must still be used - abandoning it gives up the property it was adopted for"
test -L /usr/local/bin/digs   || fail "a safe veneer must get the symlink back"
case "$(readlink -f /usr/local/bin/digs)" in
  /opt/dig/bin/*) ;;
  *) fail "the restored link must resolve into the protected root" ;;
esac
echo "safe-veneer control verified: mechanism=veneer_links, link restored into the protected root"

note "ATTEMPT 2 (G2): the attacker owns the PARENT of the install root and swaps the whole directory"
# Write permission on /opt/dig is permission to rename /opt/dig/bin aside and substitute an attacker-owned
# directory of the same name. No race, no password.
chmod 0777 /opt/dig
sudo -u "$ATTACKER" mv /opt/dig/bin /opt/dig/bin.orig
sudo -u "$ATTACKER" mkdir /opt/dig/bin
plant_as_attacker /opt/dig/bin/digs

set +e
"$INSTALLER" "${CLI_ONLY[@]}" --json > attempt2.json 2> attempt2.err
RC=$?
set -e
cat attempt2.err
echo "installer exit: $RC"

# `if !grep`, never `grep && fail`: under `set -e` a non-matching `grep -q` returns 1 and the
# `cmd && fail` compound then exits the script with the attempt LOOKING like it passed. That is the same
# shape as the `grep -q` SIGPIPE trap fixed in the e2e workflow, and it silently skipped every attempt
# after the first until it was caught here.
if grep -q "$MARKER" attempt2.json attempt2.err; then
  fail "root EXECUTED the attacker's binary (G2)"
fi
if grep -q 'uid=0(root)' attempt2.json attempt2.err; then
  fail "root EXECUTED the attacker's binary (G2)"
fi
# Repairing the DIRECTORY is not enough on its own: her planted FILE is inside it, and a chowned directory
# with her payload still in it is a root-owned attacker binary in the protected root, which the version
# probe would then have every reason to trust. So the CONTENTS must have been replaced too.
if grep -q "$MARKER" /opt/dig/bin/digs 2>/dev/null; then
  fail "the planted payload survived inside the protected root - repairing the directory chowned her file to root instead of replacing it"
fi
/opt/dig/bin/digs --version | grep -qv "99.0.0"   || fail "digs reports the version the attacker chose, so her binary is still what runs"
# The install REPAIRS a DIG-owned level rather than accepting it, so /opt/dig must come back root-owned.
test "$(stat -c '%U' /opt/dig)" = root || fail "/opt/dig was left owned by $ATTACKER"
test -z "$(find /opt/dig -maxdepth 0 \( -perm -0002 -o -perm -0020 \))" \
  || fail "/opt/dig was left group- or world-writable, so the swap can simply be repeated"

note "CONTROL 2: with the chain repaired, the same install must succeed"
rm -rf /opt/dig/bin.orig
"$INSTALLER" "${CLI_ONLY[@]}" --json > control2.json
jq -e '.ok == true'           control2.json || fail "the repaired chain must install"
jq -e '.result.ready == true' control2.json || fail "the repaired chain must be ready"
test -L /usr/local/bin/digs   || fail "the repaired install planted no veneer link"

note "ATTEMPT 3: the attacker cannot touch the protected root at all"
if sudo -u "$ATTACKER" sh -c 'echo x > /opt/dig/bin/planted' 2>/dev/null; then
  fail "$ATTACKER wrote inside the protected root"
fi
if sudo -u "$ATTACKER" sh -c 'mv /opt/dig/bin /opt/dig/bin.stolen' 2>/dev/null; then
  fail "$ATTACKER renamed the protected root - the parent is writable"
fi

note "All escalation attempts refused, and every control succeeded"
