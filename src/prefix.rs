use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Prefix {
    pub address: IpAddr,
    pub length: u8,
}

impl Prefix {
    pub fn network(address: IpAddr, length: u8) -> Self {

        // The address with every bit past the prefix length cleared
        let address = match address {
            IpAddr::V4(address) => IpAddr::V4(Ipv4Addr::from(u32::from(address) & u32::MAX.checked_shl(32 - length as u32).unwrap_or(0))),
            IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(u128::from(address) & u128::MAX.checked_shl(128 - length as u32).unwrap_or(0))),
        };
        Self { address, length }
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub fn contains(&self, other: &Prefix) -> bool {

        // Both addresses are compared as their top bits, up to this prefix's length
        let (own_bits, other_bits, width) = match (self.address, other.address) {
            (IpAddr::V4(own), IpAddr::V4(other)) => (u32::from(own) as u128, u32::from(other) as u128, 32),
            (IpAddr::V6(own), IpAddr::V6(other)) => (u128::from(own), u128::from(other), 128),
            _ => return false,
        };
        let shift = width - self.length as u32;
        self.length <= other.length && own_bits.checked_shr(shift).unwrap_or(0) == other_bits.checked_shr(shift).unwrap_or(0)
    }
}

impl FromStr for Prefix {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, length) = text.split_once('/').ok_or_else(|| format!("{:?} has no prefix length", text))?;
        let address: IpAddr = address.parse().map_err(|_| format!("{:?} isn't an IP address", address))?;
        let length: u8 = length.parse().map_err(|_| format!("{:?} isn't a prefix length", length))?;
        if length > if address.is_ipv6() { 128 } else { 32 } {
            return Err(format!("{} is too long", text));
        }
        Ok(Self { address, length })
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.length)
    }
}
