#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#![allow(clippy::missing_safety_doc)]
include!(concat!(env!("OUT_DIR"), "/sockaddr.rs"));

use std::error::Error;
use std::convert::TryInto;
use std::net::{Ipv4Addr,Ipv6Addr,SocketAddrV4,SocketAddrV6};
use std::mem::{size_of,transmute};

/*
pub struct SocketAddrLL {
    pub protocol: u16,
    pub ifindex: u32,
    pub hatype: u16,
    pub pkttype: u8,
    pub addr: Vec<u8>,
}
*/

#[derive(Debug,PartialEq)]
pub struct SocketAddrLocal {
    pub path: Vec<u8>,
}

#[derive(Debug,PartialEq)]
pub struct SocketAddrAX25 {
    pub call: [u8;7],
}

#[derive(Debug,PartialEq)]
pub struct SocketAddrATMPVC {
    pub itf: i16,
    pub vpi: i16,
    pub vci: i32,
}

#[derive(Debug,PartialEq)]
pub struct SocketAddrIPX {
    pub port: u16,
    pub network: u32,
    pub node: [u8;6],
    pub typ: u8,
}

#[derive(Debug,PartialEq)]
pub struct SocketAddrX25 {
    pub address: [u8;16],
}

#[derive(Debug,PartialEq)]
pub struct SocketAddrVM {
    pub port: u32,
    pub cid: u32,
}

#[derive(Debug,PartialEq)]
pub struct SocketAddrNL {
    pub pid: u32,
    pub groups: u32,
}

#[derive(Debug,PartialEq)]
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

fn get_sock<T>(buf: &[u8]) -> Result<&T, String> {
    if buf.len() < size_of::<T>() {
        Err("buffer too short".into())
    } else {
        let sa = unsafe { &* transmute::<_,*const T>(&buf[0] as *const _) };
        Ok(sa)
    }
}

impl SocketAddr {
    pub fn parse(buf: &[u8]) -> Result<Self, Box<dyn Error>> {
        if buf.len() < 2 {
            return Err("buffer too short".into());
        }
        let fam = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as u32;
        match fam {
            AF_LOCAL => {
                let sa = get_sock::<sockaddr_un>(buf)?;
                let path: Vec<u8> = if sa.sun_path[0] == 0 {
                    &sa.sun_path[1..]
                } else {
                    &sa.sun_path[..]
                }.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
                Ok(SocketAddr::Local(SocketAddrLocal{path}))
            },
            AF_INET => {
                let sa = get_sock::<sockaddr_in>(buf)?;
                Ok(SocketAddr::Inet(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port as u16)
                )))
            },
            AF_AX25 => {
                let sa = get_sock::<sockaddr_ax25>(buf)?;
                let mut call = [0u8; 7];
                for (i, v) in sa.sax25_call.ax25_call.iter().enumerate() {
                    call[i] = *v as u8;
                }
                Ok(SocketAddr::AX25(SocketAddrAX25{call}))
            },
            AF_IPX => {
                let sa = get_sock::<sockaddr_ipx>(buf)?;
                Ok(SocketAddr::IPX(SocketAddrIPX{
                    port: u16::from_be(sa.sipx_port),
                    network: u32::from_be(sa.sipx_network),
                    node: sa.sipx_node,
                    typ: sa.sipx_type,
                }))
            },
            AF_ATMPVC => {
                let sa = get_sock::<sockaddr_atmpvc>(buf)?;
                Ok(SocketAddr::ATMPVC(SocketAddrATMPVC{
                    itf: sa.sap_addr.itf,
                    vpi: sa.sap_addr.vpi,
                    vci: sa.sap_addr.vci,
                }))
            },
            AF_X25 => {
                let sa = get_sock::<sockaddr_x25>(buf)?;
                let mut address = [0u8; 16];
                for (i, v) in sa.sx25_addr.x25_addr.iter().enumerate() {
                    address[i] = *v as u8;
                }
                Ok(SocketAddr::X25(SocketAddrX25{address}))
            },
            AF_INET6 => {
                let sa = get_sock::<sockaddr_in6>(buf)?;
                let addr = unsafe { sa.sin6_addr.in6_u.u6_addr8 };
                Ok(SocketAddr::Inet6(SocketAddrV6::new(
                    Ipv6Addr::from(addr),
                    u16::from_be(sa.sin6_port as u16),
                    u32::from_be(sa.sin6_flowinfo),
                    sa.sin6_scope_id
                )))
            },
            AF_NETLINK => {
                let sa = get_sock::<sockaddr_nl>(buf)?;
                Ok(SocketAddr::Netlink(SocketAddrNL{pid: sa.nl_pid, groups: sa.nl_groups}))
            },
            AF_VSOCK => {
                let sa = get_sock::<sockaddr_vm>(buf)?;
                Ok(SocketAddr::VM(SocketAddrVM{ port: sa.svm_port, cid: sa.svm_cid } ))
            },
            _ => Err(format!("unrecognized socket family {}", fam).into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_syslog() -> Result<(), Box<dyn Error>> {
        // taken from testdata/record-connect-unix-raw.txt
        let buf = b"\x01\x00\x2F\x64\x65\x76\x2F\x6C\x6F\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let s = SocketAddr::parse(&buf[..])?;
        assert_eq!(s, SocketAddr::Local(SocketAddrLocal{path: Vec::from(*b"/dev/log")}));
        Ok(())
    }
}
