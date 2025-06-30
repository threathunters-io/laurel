#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
include!(concat!(env!("OUT_DIR"), "/sockaddr.rs"));

use std::convert::TryInto;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use thiserror::Error;

use ipnetwork::{IpNetwork, Ipv6Network};

use serde_with::{DeserializeFromStr, SerializeDisplay};

/*
pub struct SocketAddrLL {
    pub protocol: u16,
    pub ifindex: u32,
    pub hatype: u16,
    pub pkttype: u8,
    pub addr: Vec<u8>,
}
*/

#[derive(Debug, PartialEq, Eq)]
pub struct SocketAddrLocal {
    pub path: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SocketAddrAX25 {
    pub call: [u8; 7],
}

#[derive(Debug, PartialEq, Eq)]
pub struct SocketAddrATMPVC {
    pub itf: i16,
    pub vpi: i16,
    pub vci: i32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SocketAddrIPX {
    pub port: u16,
    pub network: u32,
    pub node: [u8; 6],
    pub typ: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SocketAddrX25 {
    pub address: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub struct SocketAddrVM {
    pub port: u32,
    pub cid: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SocketAddrNL {
    pub pid: u32,
    pub groups: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocketAddr {
    Local(SocketAddrLocal),
    Inet(SocketAddrV4),
    AX25(SocketAddrAX25),
    ATMPVC(SocketAddrATMPVC),
    X25(SocketAddrX25),
    IPX(SocketAddrIPX),
    Inet6(SocketAddrV6),
    Netlink(SocketAddrNL),
    VM(SocketAddrVM),
}

#[derive(Debug, Error)]
pub enum SocketAddrError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("unrecognized socket family {0}")]
    UnrecognizedFamily(u16),
}

fn get_sock<T: Sized>(buf: &[u8]) -> Result<T, SocketAddrError> {
    if buf.len() < std::mem::size_of::<T>() {
        Err(SocketAddrError::BufferTooShort)
    } else {
        let sa = unsafe { std::ptr::read(&buf[0] as *const _ as _) };
        Ok(sa)
    }
}

impl SocketAddr {
    pub fn parse(buf: &[u8]) -> Result<Self, SocketAddrError> {
        if buf.len() < 2 {
            return Err(SocketAddrError::BufferTooShort);
        }
        let fam = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as u32;
        match fam {
            AF_LOCAL => {
                let sa = get_sock::<sockaddr_un>(buf)?;
                let path: Vec<u8> = if sa.sun_path[0] == 0 {
                    &sa.sun_path[1..]
                } else {
                    &sa.sun_path[..]
                }
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
                Ok(SocketAddr::Local(SocketAddrLocal { path }))
            }
            AF_INET => {
                let sa = get_sock::<sockaddr_in>(buf)?;
                Ok(SocketAddr::Inet(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port),
                )))
            }
            AF_AX25 => {
                let sa = get_sock::<sockaddr_ax25>(buf)?;
                let mut call = [0u8; 7];
                for (i, v) in sa.sax25_call.ax25_call.iter().enumerate() {
                    call[i] = *v as u8;
                }
                Ok(SocketAddr::AX25(SocketAddrAX25 { call }))
            }
            AF_IPX => {
                let sa = get_sock::<sockaddr_ipx>(buf)?;
                Ok(SocketAddr::IPX(SocketAddrIPX {
                    port: u16::from_be(sa.sipx_port),
                    network: u32::from_be(sa.sipx_network),
                    node: sa.sipx_node,
                    typ: sa.sipx_type,
                }))
            }
            AF_ATMPVC => {
                let sa = get_sock::<sockaddr_atmpvc>(buf)?;
                Ok(SocketAddr::ATMPVC(SocketAddrATMPVC {
                    itf: sa.sap_addr.itf,
                    vpi: sa.sap_addr.vpi,
                    vci: sa.sap_addr.vci,
                }))
            }
            AF_X25 => {
                let sa = get_sock::<sockaddr_x25>(buf)?;
                let mut address = [0u8; 16];
                for (i, v) in sa.sx25_addr.x25_addr.iter().enumerate() {
                    address[i] = *v as u8;
                }
                Ok(SocketAddr::X25(SocketAddrX25 { address }))
            }
            AF_INET6 => {
                let sa = get_sock::<sockaddr_in6>(buf)?;
                let addr = unsafe { sa.sin6_addr.in6_u.u6_addr8 };
                Ok(SocketAddr::Inet6(SocketAddrV6::new(
                    Ipv6Addr::from(addr),
                    u16::from_be(sa.sin6_port),
                    u32::from_be(sa.sin6_flowinfo),
                    sa.sin6_scope_id,
                )))
            }
            AF_NETLINK => {
                let sa = get_sock::<sockaddr_nl>(buf)?;
                Ok(SocketAddr::Netlink(SocketAddrNL {
                    pid: sa.nl_pid,
                    groups: sa.nl_groups,
                }))
            }
            AF_VSOCK => {
                let sa = get_sock::<sockaddr_vm>(buf)?;
                Ok(SocketAddr::VM(SocketAddrVM {
                    port: sa.svm_port,
                    cid: sa.svm_cid,
                }))
            }
            _ => Err(SocketAddrError::UnrecognizedFamily(fam as _)),
        }
    }
}

/// An expression that is used to filter based on Socket Addresses
///
/// IPv4 and IPv6 ranges with or without ports are supported.
#[derive(Clone, Debug, DeserializeFromStr, SerializeDisplay)]
pub enum SocketAddrMatcher {
    Net(ipnetwork::IpNetwork),
    Port(u16),
    NetPort(ipnetwork::IpNetwork, u16),
}

impl Display for SocketAddrMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SocketAddrMatcher::Net(n) => write!(f, "{n}"),
            SocketAddrMatcher::Port(p) => write!(f, "*:{p}"),
            SocketAddrMatcher::NetPort(IpNetwork::V4(n), p) => write!(f, "{n}:{p}"),
            SocketAddrMatcher::NetPort(IpNetwork::V6(n), p) => write!(f, "[{n}]:{p}"),
        }
    }
}

impl SocketAddrMatcher {
    pub fn matches(&self, addr: &SocketAddr) -> bool {
        let (addr, port) = match addr {
            SocketAddr::Inet(s) => (IpAddr::V4(*s.ip()), s.port()),
            SocketAddr::Inet6(s) => (IpAddr::V6(*s.ip()), s.port()),
            _ => return false,
        };

        match self {
            SocketAddrMatcher::Net(n) => n.contains(addr),
            SocketAddrMatcher::Port(p) => *p == port,
            SocketAddrMatcher::NetPort(n, p) => n.contains(addr) && *p == port,
        }
    }
}

#[derive(Debug, Error)]
pub enum SocketAddrMatchParseError {
    #[error(transparent)]
    IpNetworkError(#[from] ipnetwork::IpNetworkError),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
}

impl FromStr for SocketAddrMatcher {
    type Err = SocketAddrMatchParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("*:") {
            let p: u16 = s.parse()?;
            Ok(SocketAddrMatcher::Port(p))
        } else if let Some((sn, sp)) = s.strip_prefix("[").and_then(|s| s.split_once("]:")) {
            let n: Ipv6Network = sn.parse()?;
            let p: u16 = sp.parse()?;
            Ok(SocketAddrMatcher::NetPort(IpNetwork::V6(n), p))
        } else if let Ok(n) = s.parse::<Ipv6Network>() {
            Ok(SocketAddrMatcher::Net(IpNetwork::V6(n)))
        } else if let Some((sn, sp)) = s.split_once(":") {
            let n: IpNetwork = sn.parse()?;
            let p: u16 = sp.parse()?;
            Ok(SocketAddrMatcher::NetPort(n, p))
        } else {
            Ok(SocketAddrMatcher::Net(s.parse::<IpNetwork>()?))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_syslog() -> Result<(), SocketAddrError> {
        // taken from testdata/record-connect-unix-raw.txt
        #[cfg(target_endian = "little")]
        {
            assert_eq!(
                SocketAddr::parse(b"\x01\x00\x2F\x64\x65\x76\x2F\x6C\x6F\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?,
                SocketAddr::Local(SocketAddrLocal {
                    path: Vec::from(*b"/dev/log")
                })
            );
        }

        // taken from testdata/record-bind-ipv4-bigendian.txt
        #[cfg(target_endian = "big")]
        {
            assert_eq!(
                SocketAddr::parse(
                    b"\x00\x02\xD9\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                )?,
                SocketAddr::Inet("0.0.0.0:55555".parse().unwrap())
            );
        }

        Ok(())
    }

    #[test]
    fn socketaddr_matcher_parse() {
        for s in &[
            "127.0.0.0/8",
            "192.168.0.0/24:443",
            "::/64",
            "[2a00:1450:4001:82f::200e]:443",
            "*:53",
        ] {
            let sam: SocketAddrMatcher =
                s.parse().unwrap_or_else(|_| panic!("could not parse {s}"));
            println!("{sam:?}");
        }
    }

    #[test]
    fn socketaddr_matcher() {
        for s in &[
            ("127.0.0.0/8", "127.0.0.1:9999"),
            ("192.168.0.0/24:443", "192.168.0.42:443"),
            ("::/64", "[::1]:80"),
            ("[fe80::/10]:53", "[fe80::abad:1dea]:53"),
            ("*:53", "192.168.1.1:53"),
            ("*:53", "[::1]:53"),
            ("::ffff:127.0.0.0/104", "[::ffff:127.0.0.1]:80"),
        ] {
            let sam: SocketAddrMatcher =
                s.0.parse()
                    .unwrap_or_else(|_| panic!("could not parse {}", s.0));
            let sa: SocketAddr = match s.1.parse() {
                Ok(std::net::SocketAddr::V4(sa)) => SocketAddr::Inet(sa),
                Ok(std::net::SocketAddr::V6(sa)) => SocketAddr::Inet6(sa),
                _ => panic!("could not parse {}", s.1),
            };
            println!("{sam:?}, {sa:?}");
            assert!(sam.matches(&sa), "{} does not match {}", s.0, s.1);
        }
    }
}
