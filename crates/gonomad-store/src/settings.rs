//! The daemon's key/value settings table.
//!
//! Deliberately stringly-typed and deliberately small. Configuration proper
//! lives in a TOML file the user edits (`ARCHITECTURE.md` §5.4); this table is
//! for the handful of values the daemon itself writes and must survive a
//! restart — the last-used workspace, a rotation counter, an audit head
//! receipt.
//!
//! **Not a secret store.** Private keys live in the OS keychain (§3.3) and file
//! content lives on disk (§16.1). A value written here is readable by anyone
//! who can read the database file.

use rusqlite::{Connection, OptionalExtension};

use crate::error::Result;

/// The settings repository. Obtained from [`crate::Store::settings`].
pub struct Settings<'a> {
    conn: &'a Connection,
}

impl<'a> Settings<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Reads a value, or `None` when the key is unset.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StoreError::Database`] on engine failure.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// Reads a value, falling back to `default` when unset.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StoreError::Database`] on engine failure.
    pub fn get_or(&self, key: &str, default: &str) -> Result<String> {
        Ok(self.get(key)?.unwrap_or_else(|| default.to_owned()))
    }

    /// Writes a value, replacing any existing one.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StoreError::Database`] on engine failure.
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Deletes a key. Returns `false` when it was not set.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StoreError::Database`] on engine failure.
    pub fn remove(&self, key: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM settings WHERE key = ?1", [key])?
            > 0)
    }

    /// Every setting, sorted by key.
    ///
    /// Sorted rather than arbitrary because this feeds `gonomad status` output
    /// and diffing two machines' settings should not be defeated by row order.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StoreError::Database`] on engine failure.
    pub fn all(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM settings ORDER BY key ASC")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::Store;

    fn on_disk() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("gonomad.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn set_get_and_overwrite() {
        let (_dir, store) = on_disk();
        let settings = store.settings();
        assert_eq!(settings.get("workspace").unwrap(), None);

        settings.set("workspace", "C:/code/gonomad").unwrap();
        assert_eq!(
            settings.get("workspace").unwrap().as_deref(),
            Some("C:/code/gonomad")
        );

        settings.set("workspace", "C:/code/other").unwrap();
        assert_eq!(
            settings.get("workspace").unwrap().as_deref(),
            Some("C:/code/other")
        );
        assert_eq!(
            settings.all().unwrap().len(),
            1,
            "upsert must not duplicate"
        );
    }

    #[test]
    fn defaults_and_removal() {
        let (_dir, store) = on_disk();
        let settings = store.settings();
        assert_eq!(settings.get_or("theme", "dark").unwrap(), "dark");
        settings.set("theme", "light").unwrap();
        assert_eq!(settings.get_or("theme", "dark").unwrap(), "light");

        assert!(settings.remove("theme").unwrap());
        assert!(!settings.remove("theme").unwrap());
        assert_eq!(settings.get_or("theme", "dark").unwrap(), "dark");
    }

    #[test]
    fn listing_is_sorted_by_key() {
        let (_dir, store) = on_disk();
        let settings = store.settings();
        for key in ["zebra", "apple", "mango"] {
            settings.set(key, key).unwrap();
        }
        let keys: Vec<String> = settings
            .all()
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, vec!["apple", "mango", "zebra"]);
    }

    #[test]
    fn values_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gonomad.db");
        Store::open(&path)
            .unwrap()
            .settings()
            .set("audit.head", "deadbeef")
            .unwrap();
        assert_eq!(
            Store::open(&path)
                .unwrap()
                .settings()
                .get("audit.head")
                .unwrap()
                .as_deref(),
            Some("deadbeef")
        );
    }

    #[test]
    fn empty_values_are_preserved_and_distinct_from_absent() {
        let (_dir, store) = on_disk();
        store.settings().set("k", "").unwrap();
        assert_eq!(store.settings().get("k").unwrap(), Some(String::new()));
        assert_eq!(store.settings().get("absent").unwrap(), None);
    }
}
