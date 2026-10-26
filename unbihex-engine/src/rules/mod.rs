//! Large routing lists: geosite/geoip (v2fly) and sing-box `.srs` rule-sets.
//!
//! Everything is kept compact (succinct tries, merged ranges) so that big lists
//! fit the memory budget of mobile VPN extensions.

pub mod geodata;
pub mod ipset;
pub mod srs;
pub mod succinct;

pub use geodata::{GeoCache, IpList, SiteList};
pub use ipset::IpSet;
pub use srs::RuleSet;
pub use succinct::DomainSet;
