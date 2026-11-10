//! Route representation and the diff applied by a connect/teardown cycle.

use std::net::IpAddr;

use crate::TunError;

/// One IPv4 or IPv6 route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Route {
    /// Destination network address.
    pub destination: IpAddr,
    /// Prefix length in bits (0..=32 for IPv4, 0..=128 for IPv6).
    pub prefix_len: u8,
    /// Optional next hop. `None` means an on-link route.
    pub gateway: Option<IpAddr>,
    /// Route metric.
    pub metric: u32,
}

impl Route {
    /// Build and validate a route.
    pub fn new(
        destination: IpAddr,
        prefix_len: u8,
        gateway: Option<IpAddr>,
        metric: u32,
    ) -> Result<Self, TunError> {
        let max_prefix = match destination {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(TunError::InvalidConfig(format!(
                "prefix /{prefix_len} is invalid for {destination}"
            )));
        }
        if let Some(gateway) = gateway {
            let family_matches = matches!(
                (destination, gateway),
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
            );
            if !family_matches {
                return Err(TunError::InvalidConfig(format!(
                    "gateway {gateway} and destination {destination} are different address families"
                )));
            }
        }
        Ok(Self {
            destination,
            prefix_len,
            gateway,
            metric,
        })
    }

    /// Build an on-link route with metric zero.
    pub fn on_link(destination: IpAddr, prefix_len: u8) -> Result<Self, TunError> {
        Self::new(destination, prefix_len, None, 0)
    }
}

/// A route observed in the platform table before it was displaced.
///
/// The fields mirror what `route -n get` (macOS) and `ip route show` (Linux)
/// report. They are persisted in the journal so a disconnect or crash recovery
/// can put the original route back exactly as it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    /// Destination network address.
    pub destination: IpAddr,
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// Next hop, when the original route had one.
    pub gateway: Option<IpAddr>,
    /// Interface that owned the route.
    pub interface: String,
    /// Platform flags, for the journal and diagnostics.
    pub flags: String,
    /// Route metric, when the platform reports one.
    pub metric: u32,
}

impl RouteRecord {
    /// The destination in CIDR notation.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.destination, self.prefix_len)
    }

    /// Convert the record back into an applyable route.
    pub fn to_route(&self) -> Result<Route, TunError> {
        Route::new(self.destination, self.prefix_len, self.gateway, self.metric)
    }

    /// Whether the recorded route was scoped to its interface.
    pub fn is_ifscoped(&self) -> bool {
        self.flags
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|flag| flag.eq_ignore_ascii_case("IFSCOPE"))
    }

    /// Whether this record describes the same destination and prefix.
    pub fn same_prefix(&self, route: &Route) -> bool {
        self.destination == route.destination && self.prefix_len == route.prefix_len
    }
}

/// Routes to install and routes to remove to move from one set to another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteDiff {
    /// Present in the desired set but not the current one.
    pub to_add: Vec<Route>,
    /// Present in the current set but not the desired one.
    pub to_remove: Vec<Route>,
}

impl RouteDiff {
    /// Whether no change is required.
    pub fn is_empty(&self) -> bool {
        self.to_add.is_empty() && self.to_remove.is_empty()
    }
}

/// Compute the set difference between the current and desired routes.
///
/// Order is preserved from the input vectors and duplicates are collapsed.
pub fn diff_routes(current: &[Route], desired: &[Route]) -> RouteDiff {
    let mut to_add = Vec::new();
    for route in desired {
        if !current.contains(route) && !to_add.contains(route) {
            to_add.push(route.clone());
        }
    }

    let mut to_remove = Vec::new();
    for route in current {
        if !desired.contains(route) && !to_remove.contains(route) {
            to_remove.push(route.clone());
        }
    }

    RouteDiff { to_add, to_remove }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn route(octet: u8, prefix_len: u8) -> Route {
        Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, octet, 0)), prefix_len).expect("route")
    }

    #[test]
    fn identical_sets_need_no_change() {
        let routes = vec![route(1, 8), route(2, 16)];
        let diff = diff_routes(&routes, &routes);
        assert!(diff.is_empty());
    }

    #[test]
    fn additions_and_removals_are_detected() {
        let current = vec![route(1, 8), route(2, 16)];
        let desired = vec![route(2, 16), route(3, 24)];
        let diff = diff_routes(&current, &desired);

        assert_eq!(diff.to_add, vec![route(3, 24)]);
        assert_eq!(diff.to_remove, vec![route(1, 8)]);
    }

    #[test]
    fn duplicate_desired_routes_are_collapsed() {
        let current = vec![];
        let desired = vec![route(1, 8), route(1, 8)];
        let diff = diff_routes(&current, &desired);
        assert_eq!(diff.to_add, vec![route(1, 8)]);
        assert!(diff.to_remove.is_empty());
    }

    #[test]
    fn metric_changes_replace_the_route() {
        let current =
            vec![Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, None, 0).expect("route")];
        let desired =
            vec![Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, None, 100).expect("route")];
        let diff = diff_routes(&current, &desired);
        assert_eq!(diff.to_add.len(), 1);
        assert_eq!(diff.to_remove.len(), 1);
        assert_eq!(diff.to_add[0].metric, 100);
    }

    #[test]
    fn rejects_bad_prefix_and_family_mismatch() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let v6 = IpAddr::V6("2001:db8::".parse().expect("v6"));
        assert!(Route::on_link(v4, 33).is_err());
        assert!(Route::on_link(v6, 129).is_err());
        assert!(Route::new(v4, 8, Some(v6), 0).is_err());
        assert!(Route::on_link(v4, 8).is_ok());
    }
}
