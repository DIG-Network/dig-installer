//! Windows `ExtensionInstallForcelist` writer (issue #612).
//!
//! Chromium-family policy on Windows lives under
//! `HKLM\SOFTWARE\Policies\<vendor>\<product>`; the force-install list is the
//! subkey `…\ExtensionInstallForcelist`, whose values are numbered strings
//! (`"1"`, `"2"`, …) each holding one `"<id>;<update_url>"` entry.
//!
//! We MERGE: our single entry is added as a new numbered value beside whatever
//! an enterprise already set, and we recognize our own entry solely by its
//! canonical DIG id ([`super::is_our_entry`]) so removal deletes exactly ours
//! and never truncates an org's forcelist. We never delete the
//! `ExtensionInstallForcelist` subkey itself (a possibly-empty key is far safer
//! than nuking a key we do not exclusively own) — mirroring the DoH writer.

use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

use super::{forcelist_entry, is_our_entry, Channel, ForcelistAction, ForcelistOutcome};

/// The forcelist subkey under a browser's policy key.
const FORCELIST_SUBKEY: &str = "ExtensionInstallForcelist";

/// Force-install the extension for `channel` into the browser rooted at the
/// `HKLM`-relative `policy_key` (e.g. `SOFTWARE\Policies\Google\Chrome`).
pub fn apply(policy_key: &str, channel: Channel) -> ForcelistOutcome {
    apply_under(&RegKey::predef(HKEY_LOCAL_MACHINE), policy_key, channel)
}

/// Remove the DIG forcelist entry from the browser rooted at `policy_key`.
pub fn remove(policy_key: &str) -> ForcelistOutcome {
    remove_under(&RegKey::predef(HKEY_LOCAL_MACHINE), policy_key)
}

fn forcelist_key_path(policy_key: &str) -> String {
    format!(r"{policy_key}\{FORCELIST_SUBKEY}")
}

/// Testable core of [`apply`], parametrized on the hive so unit tests run
/// against a temporary `HKCU` test key rather than needing Administrator + HKLM.
fn apply_under(hive: &RegKey, policy_key: &str, channel: Channel) -> ForcelistOutcome {
    let key_path = forcelist_key_path(policy_key);
    let entry = forcelist_entry(channel);

    let (key, _disp) = match hive.create_subkey(&key_path) {
        Ok(k) => k,
        Err(e) => return failed(key_path, &format!("open/create: {e}")),
    };

    // Snapshot existing numbered entries so we can MERGE, never clobber.
    let entries = numbered_entries(&key);

    // Idempotent / channel-switch: if we already own an entry, update it in
    // place (or leave it) — never add a duplicate.
    if let Some((name, current)) = entries.iter().find(|(_, v)| is_our_entry(v)) {
        if current == &entry {
            return outcome(
                key_path,
                ForcelistAction::AlreadyPresent,
                "dig entry already current",
            );
        }
        return match key.set_value(name, &entry) {
            Ok(()) => outcome(
                key_path,
                ForcelistAction::Updated,
                "replaced dig entry's update_url; a nightly<->stable switch needs the staged \
                 reinstall (forcelist::reinstall, driven by #613) to actually cross channels",
            ),
            Err(e) => failed(key_path, &format!("update value {name}: {e}")),
        };
    }

    // Fresh add: our entry goes at the next free numbered slot, leaving every
    // pre-existing (org) entry exactly where it is.
    let name = next_free_name(&entries);
    match key.set_value(&name, &entry) {
        Ok(()) => outcome(
            key_path,
            ForcelistAction::Wrote,
            "added dig entry beside existing forcelist",
        ),
        Err(e) => failed(key_path, &format!("set value {name}: {e}")),
    }
}

/// Testable core of [`remove`], parametrized on the hive.
fn remove_under(hive: &RegKey, policy_key: &str) -> ForcelistOutcome {
    let key_path = forcelist_key_path(policy_key);
    let key = match hive.open_subkey_with_flags(&key_path, KEY_READ | KEY_SET_VALUE) {
        Ok(k) => k,
        // No forcelist subkey at all — nothing of ours to remove.
        Err(_) => {
            return outcome(
                key_path,
                ForcelistAction::NothingToRemove,
                "no forcelist key",
            )
        }
    };

    // Delete ONLY the numbered values that are ours; leave every foreign entry
    // (and the subkey itself) intact.
    let ours: Vec<String> = numbered_entries(&key)
        .into_iter()
        .filter(|(_, v)| is_our_entry(v))
        .map(|(name, _)| name)
        .collect();

    if ours.is_empty() {
        return outcome(
            key_path,
            ForcelistAction::NothingToRemove,
            "no dig entry present",
        );
    }
    for name in &ours {
        if let Err(e) = key.delete_value(name) {
            return failed(key_path, &format!("delete value {name}: {e}"));
        }
    }
    outcome(
        key_path,
        ForcelistAction::Removed,
        "removed dig entry; org forcelist preserved",
    )
}

/// Every `(value-name, value-data)` currently under the forcelist key. Only
/// string values are relevant (forcelist entries are `REG_SZ`).
fn numbered_entries(key: &RegKey) -> Vec<(String, String)> {
    key.enum_values()
        .filter_map(Result::ok)
        .filter_map(|(name, _val)| key.get_value::<String, _>(&name).ok().map(|v| (name, v)))
        .collect()
}

/// The smallest positive integer name not already used, as a string. Chromium
/// numbers forcelist values `1..`; we slot ours at the first free index so the
/// list stays contiguous without renumbering (never touching) org entries.
fn next_free_name(entries: &[(String, String)]) -> String {
    let used: std::collections::BTreeSet<u32> = entries
        .iter()
        .filter_map(|(n, _)| n.parse::<u32>().ok())
        .collect();
    let mut n = 1u32;
    while used.contains(&n) {
        n += 1;
    }
    n.to_string()
}

fn outcome(location: String, action: ForcelistAction, note: &str) -> ForcelistOutcome {
    ForcelistOutcome {
        location,
        action,
        note: note.to_string(),
    }
}

fn failed(location: String, note: &str) -> ForcelistOutcome {
    outcome(location, ForcelistAction::Failed, note)
}

#[cfg(test)]
mod tests {
    use super::super::{is_our_entry, EXTENSION_ID};
    use super::*;
    use winreg::enums::HKEY_CURRENT_USER;

    /// A throwaway HKCU test root, deleted on drop — lets the registry writer be
    /// exercised without Administrator or touching real HKLM policy.
    struct TestHive {
        root: RegKey,
        base: String,
    }

    impl TestHive {
        fn new(tag: &str) -> Self {
            let base = format!(
                r"Software\DIG\test\forcelist\{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            );
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let _ = hkcu.delete_subkey_all(&base);
            let (_k, _) = hkcu.create_subkey(&base).unwrap();
            TestHive {
                root: RegKey::predef(HKEY_CURRENT_USER),
                base,
            }
        }
        /// The policy-key path under our test base (stands in for
        /// `SOFTWARE\Policies\Google\Chrome`).
        fn policy_key(&self) -> String {
            format!(r"{}\Policies\Google\Chrome", self.base)
        }
        fn forcelist_values(&self) -> Vec<(String, String)> {
            let path = forcelist_key_path(&self.policy_key());
            match self.root.open_subkey(&path) {
                Ok(k) => numbered_entries(&k),
                Err(_) => Vec::new(),
            }
        }
    }

    impl Drop for TestHive {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.base);
        }
    }

    #[test]
    fn apply_writes_our_entry() {
        let h = TestHive::new("write");
        let out = apply_under(&h.root, &h.policy_key(), Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Wrote);

        let vals = h.forcelist_values();
        assert_eq!(vals.len(), 1);
        assert!(is_our_entry(&vals[0].1));
        assert!(vals[0].1.contains("stable"));
    }

    #[test]
    fn apply_is_idempotent_no_duplicate() {
        let h = TestHive::new("idem");
        apply_under(&h.root, &h.policy_key(), Channel::Stable);
        let out = apply_under(&h.root, &h.policy_key(), Channel::Stable);
        assert_eq!(out.action, ForcelistAction::AlreadyPresent);
        assert_eq!(h.forcelist_values().len(), 1, "no duplicate dig entry");
    }

    #[test]
    fn apply_switches_channel_in_place() {
        let h = TestHive::new("switch");
        apply_under(&h.root, &h.policy_key(), Channel::Stable);
        let out = apply_under(&h.root, &h.policy_key(), Channel::Nightly);
        assert_eq!(out.action, ForcelistAction::Updated);
        let vals = h.forcelist_values();
        assert_eq!(vals.len(), 1, "still one dig entry");
        assert!(vals[0].1.contains("nightly"));
    }

    #[test]
    fn apply_merges_beside_a_pre_existing_org_forcelist() {
        let h = TestHive::new("merge");
        // Seed an org's forcelist entry at "1".
        let (fkey, _) = h
            .root
            .create_subkey(forcelist_key_path(&h.policy_key()))
            .unwrap();
        fkey.set_value(
            "1",
            &"orgext000000000000000000000000000;https://org.example/updates.xml",
        )
        .unwrap();

        let out = apply_under(&h.root, &h.policy_key(), Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Wrote);

        let vals = h.forcelist_values();
        assert_eq!(vals.len(), 2, "org entry preserved + ours added");
        assert!(vals.iter().any(|(_, v)| v.starts_with("orgext")));
        assert!(vals.iter().any(|(_, v)| is_our_entry(v)));
    }

    #[test]
    fn remove_deletes_only_our_entry_and_preserves_org() {
        let h = TestHive::new("remove");
        let (fkey, _) = h
            .root
            .create_subkey(forcelist_key_path(&h.policy_key()))
            .unwrap();
        let org = "orgext000000000000000000000000000;https://org.example/updates.xml";
        fkey.set_value("1", &org).unwrap();
        apply_under(&h.root, &h.policy_key(), Channel::Stable);

        let out = remove_under(&h.root, &h.policy_key());
        assert_eq!(out.action, ForcelistAction::Removed);

        let vals = h.forcelist_values();
        assert_eq!(vals.len(), 1, "org entry survives our removal");
        assert_eq!(vals[0].1, org);
        assert!(!vals.iter().any(|(_, v)| is_our_entry(v)), "no dig residue");
    }

    #[test]
    fn remove_is_a_noop_when_no_key() {
        let h = TestHive::new("noremove");
        assert_eq!(
            remove_under(&h.root, &h.policy_key()).action,
            ForcelistAction::NothingToRemove
        );
    }

    #[test]
    fn remove_is_a_noop_when_only_org_entries() {
        let h = TestHive::new("orgonly");
        let (fkey, _) = h
            .root
            .create_subkey(forcelist_key_path(&h.policy_key()))
            .unwrap();
        fkey.set_value(
            "1",
            &"orgext000000000000000000000000000;https://org.example/updates.xml",
        )
        .unwrap();
        let out = remove_under(&h.root, &h.policy_key());
        assert_eq!(out.action, ForcelistAction::NothingToRemove);
        assert_eq!(h.forcelist_values().len(), 1, "org entry untouched");
    }

    #[test]
    fn reinstall_via_remove_then_apply_yields_one_clean_new_channel_entry() {
        // The reinstall primitive (#613) composes remove + apply; prove the
        // writer supports that transition with zero residue and no duplicate.
        let h = TestHive::new("reinstall");
        apply_under(&h.root, &h.policy_key(), Channel::Nightly);
        assert_eq!(
            remove_under(&h.root, &h.policy_key()).action,
            ForcelistAction::Removed
        );
        assert!(
            h.forcelist_values().is_empty(),
            "nightly entry fully removed first"
        );

        let out = apply_under(&h.root, &h.policy_key(), Channel::Stable);
        assert_eq!(
            out.action,
            ForcelistAction::Wrote,
            "re-added as a fresh install"
        );
        let vals = h.forcelist_values();
        assert_eq!(vals.len(), 1);
        assert!(vals[0].1.contains("stable"));
    }

    #[test]
    fn next_free_name_skips_used_slots() {
        let entries = vec![
            ("1".to_string(), "a".to_string()),
            ("3".to_string(), "b".to_string()),
        ];
        assert_eq!(next_free_name(&entries), "2");
        assert_eq!(next_free_name(&[]), "1");
    }

    #[test]
    fn written_entry_carries_the_canonical_id() {
        let h = TestHive::new("id");
        apply_under(&h.root, &h.policy_key(), Channel::Stable);
        assert!(h.forcelist_values()[0].1.starts_with(EXTENSION_ID));
    }
}
