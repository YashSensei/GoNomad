//! End-to-end demonstration of pairing and the encrypted session.
//!
//! Run with:
//!
//! ```text
//! cargo run --example pairing_demo -p gonomad-core
//! ```
//!
//! # What this is, and what it is not
//!
//! This runs the **real** pairing and session code — the same functions the
//! daemon and the phone will call. Nothing here is mocked or simulated.
//!
//! What it is *not* is a working GoNomad. Both peers live in this one process
//! and hand each other byte buffers directly, because the transport
//! (`gonomad-transport`, iroh) does not exist yet. There is no network, no
//! daemon, and no phone. This exists so the cryptography can be inspected and
//! trusted before there is anything to connect.

use gonomad_core::pairing::{ManualCode, PairingWindow};
use gonomad_core::{DeviceIdentity, Handshake, PairingSecret, PairingTicket, Purpose, Session};

/// Scratch buffer size. Generous: handshake messages are under 100 bytes.
const BUF: usize = 4096;

fn main() {
    println!("GoNomad pairing demonstration");
    println!("=============================\n");
    println!("Both peers run in this process. There is no network yet.\n");

    let daemon = DeviceIdentity::generate();
    show_identity(&daemon);

    let secret = PairingSecret::generate();
    let qr_payload = open_pairing_window(&daemon, &secret);

    let (scanned, scanned_secret) = scan_qr(&qr_payload, &daemon);
    let (phone_session, laptop_session) =
        run_handshake(&daemon, &scanned, &scanned_secret, &secret);

    exchange_a_request(phone_session, laptop_session);

    println!("Done. Every step above ran the real implementation.");
    println!("Still missing: the transport, the daemon, and the Android app.");
}

/// Step 1 — the identity `gonomad init` would create once and keep in the OS
/// keyring, never in a file.
fn show_identity(daemon: &DeviceIdentity) {
    println!("1. Laptop identity");
    println!("   device id      {}", daemon.device_id());
    println!(
        "   signing key    {}  (Ed25519, verifies approvals)",
        daemon.public_key().short()
    );
    println!(
        "   noise key      {}  (X25519, authenticates the session)\n",
        daemon.noise_public_key().short()
    );

    // These are deliberately different keys. Conflating them was a real bug.
    assert_ne!(daemon.public_key(), daemon.noise_public_key());
}

/// Step 2 — what `gonomad pair` puts on screen.
fn open_pairing_window(daemon: &DeviceIdentity, secret: &PairingSecret) -> String {
    let ticket = PairingTicket {
        daemon_key: daemon.noise_public_key(),
        addr_hints: vec!["192.168.1.42:41234".into()],
        relay_hint: Some("https://relay.example.com".into()),
    };
    let payload = ticket.encode(secret);

    println!("2. Laptop runs `gonomad pair`");
    println!("   QR payload     {payload}");
    println!(
        "   ({} chars, uppercase base32 for QR alphanumeric mode)",
        payload.len()
    );
    println!(
        "   manual code    {}   (fallback if the camera is broken)",
        ManualCode::from_secret(secret)
    );
    let attempts = gonomad_core::MAX_PAIRING_ATTEMPTS;
    println!("   window         120s, single use, {attempts} attempts\n");

    payload
}

/// Step 3 — the phone decodes the QR and learns the laptop's authentic key over
/// an optical channel. That is what defeats a network man-in-the-middle.
fn scan_qr(payload: &str, daemon: &DeviceIdentity) -> (PairingTicket, PairingSecret) {
    let (scanned, secret) = PairingTicket::decode(payload).expect("the phone decodes the QR");

    println!("3. Phone scans the QR");
    println!("   daemon key     {}", scanned.daemon_key.short());
    println!("   addr hints     {:?}", scanned.addr_hints);
    println!("   relay hint     {:?}\n", scanned.relay_hint);

    assert_eq!(scanned.daemon_key, daemon.noise_public_key());
    (scanned, secret)
}

/// Steps 4 and 5 — the Noise IKpsk2 handshake and the SAS comparison.
fn run_handshake(
    daemon: &DeviceIdentity,
    scanned: &PairingTicket,
    scanned_secret: &PairingSecret,
    laptop_secret: &PairingSecret,
) -> (Session, Session) {
    let mut window = PairingWindow::open(0);
    window.try_attempt(0).expect("within the pairing window");

    let phone = DeviceIdentity::generate();
    let psk = *scanned_secret.as_bytes();

    let mut initiator =
        Handshake::initiator(&phone, &scanned.daemon_key, Purpose::Pairing, Some(&psk))
            .expect("initiator");
    let mut responder =
        Handshake::responder(daemon, Purpose::Pairing, Some(laptop_secret.as_bytes()))
            .expect("responder");

    let mut msg1 = vec![0u8; BUF];
    let n1 = initiator
        .write_message(&[], &mut msg1)
        .expect("first flight");

    // A relay carrying this cannot tell which device is connecting: the phone's
    // static key is encrypted to the laptop's key inside the message.
    let phone_key = phone.noise_public_key();
    assert!(
        !msg1[..n1].windows(32).any(|w| w == phone_key.as_bytes()),
        "the initiator's identity must not travel in the clear"
    );

    let mut scratch = vec![0u8; BUF];
    responder
        .read_message(&msg1[..n1], &mut scratch)
        .expect("laptop reads");

    let mut msg2 = vec![0u8; BUF];
    let n2 = responder
        .write_message(&[], &mut msg2)
        .expect("second flight");
    initiator
        .read_message(&msg2[..n2], &mut scratch)
        .expect("phone reads");

    println!("4. Noise IKpsk2 handshake");
    println!("   phone -> laptop  {n1} bytes  (identity encrypted inside)");
    println!("   laptop -> phone  {n2} bytes");
    println!("   complete in one round trip\n");

    let phone_sas = initiator.sas().expect("phone SAS");
    let laptop_sas = responder.sas().expect("laptop SAS");

    println!("5. Confirm the device");
    println!("   laptop shows   {laptop_sas}");
    println!("   phone shows    {phone_sas}");
    println!(
        "   match?         {}\n",
        if phone_sas == laptop_sas {
            "yes -> tap Allow"
        } else {
            "NO -> refuse"
        }
    );

    // A man-in-the-middle proxying this produces a different transcript on each
    // side, so these digits would disagree and the human would see it.
    assert_eq!(phone_sas, laptop_sas);

    window.consume();
    println!(
        "   ticket consumed; a replay now fails: {:?}\n",
        window.try_attempt(0).unwrap_err()
    );

    (
        initiator.into_session().expect("phone"),
        responder.into_session().expect("laptop"),
    )
}

/// Step 6 — one encrypted request, and a rejected replay.
fn exchange_a_request(mut phone: Session, mut laptop: Session) {
    let request = b"fs.read src/main.rs";

    let mut ciphertext = vec![0u8; BUF];
    let n = phone.encrypt(request, &mut ciphertext).expect("encrypt");

    let mut plaintext = vec![0u8; BUF];
    let m = laptop
        .decrypt(&ciphertext[..n], &mut plaintext)
        .expect("decrypt");

    println!("6. Encrypted request");
    println!("   plaintext      {:?}", String::from_utf8_lossy(request));
    println!(
        "   on the wire    {}…  ({n} bytes)",
        hex::encode(&ciphertext[..16])
    );
    println!(
        "   laptop reads   {:?}",
        String::from_utf8_lossy(&plaintext[..m])
    );

    assert_eq!(&plaintext[..m], request);
    assert!(
        !ciphertext[..n].windows(request.len()).any(|w| w == request),
        "plaintext must not appear on the wire"
    );

    // Noise's per-message nonce counter makes in-session replay impossible.
    let replayed = laptop.decrypt(&ciphertext[..n], &mut plaintext);
    println!("   replay         rejected: {}\n", replayed.unwrap_err());
}
