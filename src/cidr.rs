//! Minimal CIDR parsing and containment, used to classify a query's source IP
//! (e.g. the WireGuard overlay range) without pulling in an external ipnet
//! crate. Both IPv4 and IPv6 are supported.

use std::net::IpAddr;

/// An IP network: a base address masked to a prefix length in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    base: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Parses `A.B.C.D/len` or `v6/len`. The base address is masked to the
    /// prefix, so `10.64.5.1/10` and `10.64.0.0/10` parse to the same network.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_str, len_str) = s
            .split_once('/')
            .ok_or_else(|| format!("missing '/prefix' in CIDR '{s}'"))?;
        let base: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid IP in CIDR '{s}'"))?;
        let prefix: u8 = len_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid prefix in CIDR '{s}'"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("prefix /{prefix} too long for CIDR '{s}'"));
        }
        Ok(Self {
            base: mask(base, prefix),
            prefix,
        })
    }

    /// Returns whether `ip` falls within this network. A v4 network never
    /// contains a v6 address and vice versa.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.prefix) == self.base
            }
            _ => false,
        }
    }
}

/// Zeroes all bits of `ip` below the top `prefix` bits.
fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4((u32::from(v4) & m).into())
        }
        IpAddr::V6(v6) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6((u128::from(v6) & m).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_masks_base() {
        // Host bits in the base are dropped.
        let a = IpCidr::parse("10.64.5.1/10").unwrap();
        let b = IpCidr::parse("10.64.0.0/10").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn overlay_range_membership() {
        let overlay = IpCidr::parse("10.64.0.0/10").unwrap();
        // 10.64.x.x .. 10.127.x.x are inside.
        assert!(overlay.contains("10.64.0.1".parse().unwrap()));
        assert!(overlay.contains("10.90.12.34".parse().unwrap()));
        assert!(overlay.contains("10.127.255.255".parse().unwrap()));
        // Neighbouring 10/8 space is outside.
        assert!(!overlay.contains("10.63.255.255".parse().unwrap()));
        assert!(!overlay.contains("10.128.0.0".parse().unwrap()));
        // Unrelated ranges (LAN, loopback, container bridge) are outside.
        assert!(!overlay.contains("192.168.122.50".parse().unwrap()));
        assert!(!overlay.contains("127.0.0.1".parse().unwrap()));
        assert!(!overlay.contains("172.16.0.5".parse().unwrap()));
    }

    #[test]
    fn family_mismatch_never_contains() {
        let v4 = IpCidr::parse("10.64.0.0/10").unwrap();
        assert!(!v4.contains("::1".parse().unwrap()));
        let v6 = IpCidr::parse("fd00::/8").unwrap();
        assert!(!v6.contains("10.64.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(IpCidr::parse("10.64.0.0").is_err()); // no prefix
        assert!(IpCidr::parse("nope/10").is_err()); // bad ip
        assert!(IpCidr::parse("10.64.0.0/40").is_err()); // prefix too long
    }
}
