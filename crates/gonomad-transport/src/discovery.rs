//! Finding the daemon on a LAN.
//!
//! # Why this module is small, and deliberately so
//!
//! The pairing QR already carries `addr_hints` (§4.6), so the *first* connection
//! after pairing needs no discovery at all, and every reconnect can start from
//! the last address that worked. Discovery only earns its keep when the daemon's
//! LAN address has changed since pairing — a recovery path, not the common one.
//!
//! So this slice provides exactly one thing: a way for the daemon to find out
//! which addresses to *put* in the QR. Getting that wrong is the failure mode
//! that actually happens, because a QR advertising `127.0.0.1` scans fine and
//! then never connects.
//!
//! # The mDNS seam
//!
//! §4.6 specifies mDNS (`_gonomad._udp.local`) advertising the node id and port.
//! It is out of scope here and is left as a documented seam rather than a stub:
//! [`crate::Discovery`] is the trait it will implement, and
//! [`crate::TcpTransport`] will consult one after its address hints are
//! exhausted. Two things a future implementer should know before starting:
//!
//! - **mDNS is blocked on many corporate and guest networks**, and on Android it
//!   requires holding a multicast lock that costs battery. It is an optimisation
//!   over pinned hints, never a replacement for them.
//! - **What is advertised is a public key and a port, not a name.** Advertising
//!   a hostname would tell everyone on the café Wi-Fi that a GoNomad daemon is
//!   running and who owns it.
//!
//! # How address enumeration works here, and its limit
//!
//! There is no dependency in the workspace that enumerates network interfaces
//! (`if-addrs` or `local-ip-address` would), and adding one for a handful of
//! hints is not obviously worth it. Instead this asks the operating system's
//! routing table the only question that matters: *if I had to reach this
//! network, which of my addresses would I use?* A UDP socket is `connect`ed to a
//! representative destination in each private range and its local address read
//! back. `connect` on a UDP socket sends no packet — it only binds the local
//! endpoint — so this touches no network and cannot block.
//!
//! **The limit, stated plainly:** this returns the addresses the OS would
//! actually route from, not every address on every interface. An interface with
//! no route to any probed range does not appear. In practice that is the right
//! answer for a hint — an address the OS would not route from is an address the
//! phone probably cannot reach either — but it is not interface enumeration, and
//! a caller that genuinely needs every address should add `if-addrs`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// Destinations probed to discover which local address would be used.
///
/// One per RFC 1918 range, plus the CGNAT range (which is where a phone on a
/// carrier-provided router often lives), plus a public address to catch the
/// default route. No packet is ever sent to any of them.
const PROBE_TARGETS: &[(Ipv4Addr, u16)] = &[
    (Ipv4Addr::new(192, 168, 0, 1), 9),
    (Ipv4Addr::new(192, 168, 1, 1), 9),
    (Ipv4Addr::new(10, 0, 0, 1), 9),
    (Ipv4Addr::new(172, 16, 0, 1), 9),
    (Ipv4Addr::new(100, 64, 0, 1), 9),
    (Ipv4Addr::new(1, 1, 1, 1), 9),
];

/// The host's usable non-loopback IPv4 addresses, in probe order.
///
/// Loopback, unspecified, broadcast and link-local (169.254/16) addresses are
/// filtered out. Link-local in particular is a trap: it is what Windows assigns
/// when DHCP fails, so it is present exactly when the machine is *least*
/// reachable, and a QR advertising one produces a pairing that scans and then
/// hangs.
///
/// Returns an empty vector when the host has no routable IPv4 address at all,
/// which is a legitimate state (no network) rather than an error.
#[must_use]
pub fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut found: Vec<Ipv4Addr> = Vec::new();
    for (ip, port) in PROBE_TARGETS {
        if let Some(addr) = route_source(SocketAddr::from((*ip, *port))) {
            if is_advertisable(addr) && !found.contains(&addr) {
                found.push(addr);
            }
        }
    }
    found
}

/// Address hints for a pairing QR, as `PairingTicket::addr_hints` strings.
///
/// The daemon calls this with its listening port and drops the result straight
/// into the ticket, so the phone's first connect is a direct dial with no
/// discovery round trip (§4.6).
#[must_use]
pub fn addr_hints(port: u16) -> Vec<String> {
    local_ipv4_addresses()
        .into_iter()
        .map(|ip| SocketAddr::from((ip, port)).to_string())
        .collect()
}

/// Which local IPv4 address the OS would use to reach `target`.
///
/// `None` when there is no route, which is the normal answer for most of the
/// probe targets on most machines.
fn route_source(target: SocketAddr) -> Option<Ipv4Addr> {
    // Bound to the unspecified address so the kernel picks the source, and to
    // port 0 so this never collides with a listener.
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(target).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

/// Whether an address is worth putting in a QR code.
fn is_advertisable(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_never_returns_an_unusable_address() {
        // The result may legitimately be empty on a CI runner with no network,
        // so the assertion is about what is *in* it, not how many.
        for ip in local_ipv4_addresses() {
            assert!(is_advertisable(ip), "{ip} should not be advertised");
        }
    }

    #[test]
    fn enumeration_has_no_duplicates() {
        // Several probe targets usually resolve to the same interface, and a QR
        // with the same address three times wastes scarce QR capacity.
        let found = local_ipv4_addresses();
        let mut unique = found.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(found.len(), unique.len());
    }

    #[test]
    fn hints_carry_the_port_and_parse_back_as_socket_addresses() {
        for hint in addr_hints(41234) {
            let addr: SocketAddr = hint.parse().expect("hint must be a socket address");
            assert_eq!(addr.port(), 41234);
        }
    }

    #[test]
    fn loopback_and_link_local_are_never_advertised() {
        assert!(!is_advertisable(Ipv4Addr::LOCALHOST));
        assert!(!is_advertisable(Ipv4Addr::UNSPECIFIED));
        assert!(!is_advertisable(Ipv4Addr::BROADCAST));
        // 169.254/16 is what Windows assigns when DHCP fails: present exactly
        // when the machine is least reachable.
        assert!(!is_advertisable(Ipv4Addr::new(169, 254, 1, 2)));
        assert!(is_advertisable(Ipv4Addr::new(192, 168, 1, 4)));
    }

    #[test]
    fn probing_does_not_block_or_panic_without_a_network() {
        // The whole point of the UDP-connect trick: no packet, no DNS, no wait.
        let started = std::time::Instant::now();
        let _ = local_ipv4_addresses();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "address probing should be effectively instant"
        );
    }
}
