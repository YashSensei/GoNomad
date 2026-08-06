//! Deterministic ("canonical") CBOR encoding for hashed structures.
//!
//! The audit chain (`ARCHITECTURE.md` §3.9) is defined as
//! `hash_n = BLAKE3(canonical_cbor(entry_n))`. That equation is only meaningful
//! if *canonical* is exact: two builds, two platforms, and two release versions
//! must produce byte-identical encodings of the same logical entry, forever.
//! Otherwise `gonomad audit verify` reports tampering when nothing was tampered
//! with, and the security property is worse than useless — it is noise a user
//! learns to ignore.
//!
//! This is a hand-written encoder rather than a `serde` one, for three reasons:
//!
//! 1. A `serde` derive makes the hash input a function of *field declaration
//!    order*, so reordering two struct fields — a refactor no reviewer would
//!    flag — silently invalidates every historical hash.
//! 2. General-purpose CBOR crates support constructs this must never emit
//!    (floats, indefinite lengths, tags, non-shortest integers). Not emitting
//!    them is easier to guarantee than to audit for.
//! 3. The encoder is 100 lines and its output is fully specified below, so it
//!    can be reimplemented from the docs by an auditor writing an independent
//!    verifier.
//!
//! ## The subset that is emitted
//!
//! RFC 8949 §4.2.1 "core deterministic encoding", restricted further:
//!
//! - Definite lengths only; no indefinite-length items.
//! - Integers in the shortest form that holds the value.
//! - Maps keyed by text strings only, sorted by the **encoded bytes of the
//!   key**, so ordering never depends on a `HashMap`'s iteration order.
//! - No floating point, ever. Floats have multiple bit patterns for the same
//!   value (and for NaN), which makes "the same logical entry" ambiguous.
//! - No tags, no simple values other than `null`.

/// A value this encoder is willing to hash.
///
/// The type deliberately cannot represent a float or an indefinite-length
/// item, so an unhashable value is a compile error rather than a subtle
/// nondeterminism.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Item<'a> {
    /// A non-negative integer (CBOR major type 0).
    Uint(u64),
    /// A signed integer (CBOR major type 0 or 1 depending on sign).
    Int(i64),
    /// A byte string (major type 2).
    Bytes(&'a [u8]),
    /// A UTF-8 text string (major type 3).
    Text(&'a str),
    /// The `null` simple value.
    Null,
}

/// Writes a CBOR argument head: the major type plus the shortest encoding of
/// `arg`.
fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    // Additional-information values from RFC 8949 §3: 0..=23 inline, then
    // 24/25/26/27 for a 1/2/4/8-byte argument. Written in hex because these
    // are bit patterns OR-ed into the major type, not quantities.
    //
    // Declared before the first statement: items are in scope for the whole
    // block regardless, so placing them mid-body reads as if they were
    // sequenced (clippy::items_after_statements).
    const AI_ONE_BYTE: u8 = 0x18;
    const AI_TWO_BYTES: u8 = 0x19;
    const AI_FOUR_BYTES: u8 = 0x1a;
    const AI_EIGHT_BYTES: u8 = 0x1b;

    let mt = major << 5;

    if let Ok(byte) = u8::try_from(arg) {
        if byte < AI_ONE_BYTE {
            out.push(mt | byte);
        } else {
            out.push(mt | AI_ONE_BYTE);
            out.push(byte);
        }
    } else if let Ok(short) = u16::try_from(arg) {
        out.push(mt | AI_TWO_BYTES);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(arg) {
        out.push(mt | AI_FOUR_BYTES);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(mt | AI_EIGHT_BYTES);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Encodes a length, which is always a `usize` in Rust and always fits a `u64`
/// on every target this project supports.
fn length(out: &mut Vec<u8>, major: u8, len: usize) {
    // `usize` is 16/32/64-bit on every supported target, so this conversion is
    // infallible in practice; saturating rather than panicking keeps a
    // hypothetical 128-bit target from taking down the daemon, and such a
    // value could not have been allocated anyway.
    head(out, major, u64::try_from(len).unwrap_or(u64::MAX));
}

fn encode(out: &mut Vec<u8>, item: Item<'_>) {
    match item {
        Item::Uint(v) => head(out, 0, v),
        Item::Int(v) => {
            if v < 0 {
                // CBOR negative integers encode `-1 - n`. Computing it as
                // `-(v + 1)` rather than `-1 - v` avoids overflow at i64::MIN.
                let n = -(v + 1);
                head(out, 1, u64::try_from(n).unwrap_or(u64::MAX));
            } else {
                head(out, 0, u64::try_from(v).unwrap_or(0));
            }
        }
        Item::Bytes(b) => {
            length(out, 2, b.len());
            out.extend_from_slice(b);
        }
        Item::Text(s) => {
            length(out, 3, s.len());
            out.extend_from_slice(s.as_bytes());
        }
        // Major type 7, simple value 22.
        Item::Null => out.push(0xf6),
    }
}

/// Encodes `fields` as a canonical CBOR map.
///
/// Keys are sorted by their *encoded* bytes, so the caller may list fields in
/// whatever order reads best without affecting the hash. Duplicate keys are a
/// programming error and are caught by a debug assertion; in release they would
/// produce a map that decoders reject, which is the safe direction.
pub(crate) fn map(fields: &[(&str, Item<'_>)]) -> Vec<u8> {
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(fields.len());
    for (key, value) in fields {
        let mut k = Vec::new();
        encode(&mut k, Item::Text(key));
        let mut v = Vec::new();
        encode(&mut v, *value);
        encoded.push((k, v));
    }
    encoded.sort_by(|a, b| a.0.cmp(&b.0));

    debug_assert!(
        encoded.windows(2).all(|w| w[0].0 != w[1].0),
        "canonical map has duplicate keys"
    );

    let mut out = Vec::new();
    length(&mut out, 5, encoded.len());
    for (k, v) in encoded {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(item: Item<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&mut out, item);
        out
    }

    #[test]
    fn integers_use_the_shortest_encoding() {
        // Test vectors from RFC 8949 Appendix A.
        assert_eq!(enc(Item::Uint(0)), [0x00]);
        assert_eq!(enc(Item::Uint(23)), [0x17]);
        assert_eq!(enc(Item::Uint(24)), [0x18, 0x18]);
        assert_eq!(enc(Item::Uint(255)), [0x18, 0xff]);
        assert_eq!(enc(Item::Uint(256)), [0x19, 0x01, 0x00]);
        assert_eq!(enc(Item::Uint(65535)), [0x19, 0xff, 0xff]);
        assert_eq!(enc(Item::Uint(65536)), [0x1a, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            enc(Item::Uint(4_294_967_296)),
            [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn negative_integers_match_rfc_8949() {
        assert_eq!(enc(Item::Int(-1)), [0x20]);
        assert_eq!(enc(Item::Int(-24)), [0x37]);
        assert_eq!(enc(Item::Int(-25)), [0x38, 0x18]);
        assert_eq!(enc(Item::Int(-1000)), [0x39, 0x03, 0xe7]);
    }

    #[test]
    fn extreme_integers_do_not_overflow() {
        // `-1 - i64::MIN` overflows; the encoder must not.
        assert_eq!(
            enc(Item::Int(i64::MIN)),
            [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            enc(Item::Int(i64::MAX)),
            [0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn non_negative_ints_encode_identically_whether_signed_or_not() {
        for v in [0i64, 1, 23, 24, 255, 256, 70000] {
            assert_eq!(
                enc(Item::Int(v)),
                enc(Item::Uint(u64::try_from(v).unwrap())),
                "mismatch at {v}"
            );
        }
    }

    #[test]
    fn strings_and_bytes_carry_a_definite_length() {
        assert_eq!(enc(Item::Text("")), [0x60]);
        assert_eq!(enc(Item::Text("a")), [0x61, 0x61]);
        assert_eq!(enc(Item::Bytes(&[])), [0x40]);
        assert_eq!(enc(Item::Bytes(&[1, 2, 3, 4])), [0x44, 1, 2, 3, 4]);
    }

    #[test]
    fn null_is_a_single_byte() {
        assert_eq!(enc(Item::Null), [0xf6]);
    }

    #[test]
    fn map_key_order_does_not_affect_the_encoding() {
        // The property the whole audit chain rests on: field order in the
        // source must not change the hash input.
        let a = map(&[
            ("zeta", Item::Uint(1)),
            ("alpha", Item::Text("x")),
            ("m", Item::Null),
        ]);
        let b = map(&[
            ("m", Item::Null),
            ("alpha", Item::Text("x")),
            ("zeta", Item::Uint(1)),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn map_keys_sort_by_encoded_bytes_not_by_unicode() {
        // RFC 8949 core deterministic ordering is over encoded key bytes,
        // which for text keys puts shorter keys first.
        let encoded = map(&[("bb", Item::Uint(2)), ("a", Item::Uint(1))]);
        // {"a": 1, "bb": 2}
        assert_eq!(encoded, [0xa2, 0x61, b'a', 0x01, 0x62, b'b', b'b', 0x02]);
    }

    #[test]
    fn distinct_values_produce_distinct_encodings() {
        assert_ne!(
            map(&[("op", Item::Text("fs.read"))]),
            map(&[("op", Item::Text("fs.write"))])
        );
        // A field moving between two keys must change the encoding, so a
        // relabelling attack cannot preserve the hash.
        assert_ne!(
            map(&[("a", Item::Text("x")), ("b", Item::Text("y"))]),
            map(&[("a", Item::Text("y")), ("b", Item::Text("x"))])
        );
    }

    #[test]
    fn encoding_is_stable_across_repeated_calls() {
        let once = map(&[("k", Item::Bytes(&[9; 32])), ("n", Item::Uint(7))]);
        for _ in 0..100 {
            assert_eq!(
                map(&[("k", Item::Bytes(&[9; 32])), ("n", Item::Uint(7))]),
                once
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn any_field_permutation_hashes_the_same(a: u64, b: i64, c: String) {
            let forward = map(&[
                ("a", Item::Uint(a)),
                ("b", Item::Int(b)),
                ("c", Item::Text(&c)),
            ]);
            let reverse = map(&[
                ("c", Item::Text(&c)),
                ("b", Item::Int(b)),
                ("a", Item::Uint(a)),
            ]);
            proptest::prop_assert_eq!(forward, reverse);
        }

        #[test]
        fn uint_encoding_round_trips_through_length_prefix(v: u64) {
            let bytes = enc(Item::Uint(v));
            // Shortest-form: the encoding of a smaller value is never longer.
            if v > 0 {
                proptest::prop_assert!(enc(Item::Uint(v - 1)).len() <= bytes.len());
            }
        }
    }
}
