//! The UniFFI binding generator for this crate.
//!
//! Built from `gonomad-ffi` itself so the generator and the scaffolding it
//! reads come from the same `uniffi` version. The Android build runs:
//!
//! ```text
//! cargo run -p gonomad-ffi --bin uniffi-bindgen -- \
//!     generate --library <path to libgonomad_ffi.so> --language kotlin --out-dir <dir>
//! ```
//!
//! `--library` mode reads the metadata the proc macros embedded in the compiled
//! artifact, which is why there is no `.udl` file to keep in sync.

fn main() {
    uniffi::uniffi_bindgen_main();
}
