mod bird;
mod prefix;

use clap::Parser;
use futures_util::TryStreamExt;
use prefix::Prefix;
use rtnetlink::RouteMessageBuilder;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::route::{RouteAttribute, RouteType};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

const TABLE_NAME: &str = "ingress_enforcer";

/// Drops traffic forwarded in from a BGP peer unless it's headed for a prefix exported to that peer, following Bird's exports as they change
#[derive(Parser)]
struct Args {
    /// A Bird BGP protocol and its neighbor's address, as <protocol>@<address> (may be repeated)
    #[arg(long = "peer", required = true, value_parser = parse_peer)]
    peers: Vec<(String, IpAddr)>,

    /// Bird's control socket
    #[arg(long, default_value = "/run/bird/bird.ctl")]
    bird_socket: PathBuf,

    /// Seconds between checks of Bird's exports and the firewall
    #[arg(long, default_value_t = 5)]
    interval: u64,

    /// Print the ruleset for the current exports and exit, without touching the firewall
    #[arg(long)]
    dry_run: bool,

    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

fn parse_peer(peer: &str) -> Result<(String, IpAddr), String> {
    let (protocol, address) = peer.split_once('@').filter(|(protocol, _)| !protocol.is_empty()).ok_or_else(|| format!("{:?} isn't <protocol>@<address>", peer))?;
    Ok((protocol.to_string(), address.parse().map_err(|_| format!("{:?} isn't an IP address", address))?))
}

async fn neighbor_interface(netlink: &rtnetlink::Handle, address: IpAddr, multihop: bool) -> Result<(String, u32), String> {

    // A multihop neighbor is wherever its route leads, but a direct one must be on a connected route. Otherwise the default route the
    // kernel falls back to while the neighbor's interface is down would restrict the wrong interface
    let query = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(address, if address.is_ipv6() { 128 } else { 32 })
        .map_err(|error| error.to_string())?
        .build();
    let route = netlink.route().get(query).execute().try_next().await.map_err(|error| error.to_string())?.ok_or_else(|| "has no route".to_string())?;
    if route.header.kind != RouteType::Unicast {
        return Err(format!("has a {:?} route rather than a unicast one", route.header.kind));
    }
    if !multihop && route.attributes.iter().any(|attribute| matches!(attribute, RouteAttribute::Gateway(_) | RouteAttribute::Via(_))) {
        return Err("is reached through a gateway".to_string());
    }
    let interface_index = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
        .ok_or_else(|| "has a route without an interface".to_string())?;

    // Routes only carry the interface's index, so its name comes from the link itself
    let link = netlink
        .link()
        .get()
        .match_index(interface_index)
        .execute()
        .try_next()
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("is on interface {}, which no longer exists", interface_index))?;
    let interface = link
        .attributes
        .into_iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name),
            _ => None,
        })
        .ok_or_else(|| format!("is on interface {}, which has no name", interface_index))?;
    Ok((interface, interface_index))
}

async fn connected_prefixes(netlink: &rtnetlink::Handle, interface_index: u32) -> Result<Vec<Prefix>, String> {

    // Every subnet the interface has an address in, so its link neighbors stay reachable
    let addresses: Vec<_> = netlink.address().get().set_link_index_filter(interface_index).execute().try_collect().await.map_err(|error| error.to_string())?;
    Ok(addresses
        .iter()
        .filter_map(|message| {
            message.attributes.iter().find_map(|attribute| match attribute {
                AddressAttribute::Address(address) => Some(Prefix::network(*address, message.header.prefix_len)),
                _ => None,
            })
        })
        .collect())
}

fn read_exports(bird: &mut bird::BirdClient, peer_interfaces: &BTreeMap<String, String>, link_prefixes: &BTreeMap<String, Vec<Prefix>>) -> BTreeMap<String, BTreeSet<Prefix>> {

    // Each interface may always reach its own subnets. Beyond that, a session Bird can't list exports for (down, or misnamed) contributes
    // nothing, so the rest of its interface's traffic is dropped
    let mut exports: BTreeMap<String, BTreeSet<Prefix>> = peer_interfaces
        .values()
        .map(|interface| (interface.clone(), link_prefixes.get(interface).into_iter().flatten().copied().collect()))
        .collect();
    for (protocol, interface) in peer_interfaces {
        let prefixes = bird.exported_prefixes(protocol).unwrap_or_else(|error| {
            log::warn!("Couldn't list what {} exports, so it allows nothing: {}", protocol, error);
            Vec::new()
        });
        exports.entry(interface.clone()).or_default().extend(prefixes);
    }

    // Interval sets reject overlapping elements, and a prefix inside another one is already covered by it
    for prefixes in exports.values_mut() {
        let all_prefixes = prefixes.clone();
        prefixes.retain(|prefix| !all_prefixes.iter().any(|other| other != prefix && other.contains(prefix)));
    }
    exports
}

fn render_ruleset(exports: &BTreeMap<String, BTreeSet<Prefix>>) -> String {
    let interfaces = exports.keys().map(|interface| format!("{:?}", interface)).collect::<Vec<_>>().join(", ");
    let export_set = |name: &str, address_type: &str, ipv6: bool| {
        let elements = exports
            .iter()
            .flat_map(|(interface, prefixes)| prefixes.iter().filter(move |prefix| prefix.is_ipv6() == ipv6).map(move |prefix| format!("{:?} . {}", interface, prefix)))
            .collect::<Vec<_>>();
        let elements_line = if elements.is_empty() { String::new() } else { format!("\n\t\telements = {{ {} }}", elements.join(", ")) };
        format!("set {} {{\n\t\ttype ifname . {}\n\t\tflags interval{}\n\t}}", name, address_type, elements_line)
    };

    // Until any peer's interface is known there's nothing to match on, and an empty interface set isn't valid. NATed connections are
    // let through first, since replies to them are already translated to inside addresses by the time they get here
    let rules = if exports.is_empty() {
        String::new()
    } else {
        format!(
            "\n\t\tct status & (snat | dnat) != 0 accept\n\t\tiifname {{ {interfaces} }} iifname . ip daddr != @exports_ipv4 counter drop\n\t\tiifname {{ {interfaces} }} iifname . ip6 daddr != @exports_ipv6 counter drop",
            interfaces = interfaces
        )
    };

    // The table is replaced whole in one transaction, and runs before the firewall's own forward chain
    format!(
        "table inet {table}\ndelete table inet {table}\ntable inet {table} {{\n\t{ipv4_set}\n\n\t{ipv6_set}\n\n\tchain forward {{\n\t\ttype filter hook forward priority filter - 10; policy accept;{rules}\n\t}}\n}}\n",
        table = TABLE_NAME,
        ipv4_set = export_set("exports_ipv4", "ipv4_addr", false),
        ipv6_set = export_set("exports_ipv6", "ipv6_addr", true),
        rules = rules,
    )
}

fn table_exists() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", TABLE_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn apply_ruleset(ruleset: &str) -> std::io::Result<()> {
    let mut nft = Command::new("nft").args(["-f", "-"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    nft.stdin.take().unwrap().write_all(ruleset.as_bytes())?;
    let output = nft.wait_with_output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(String::from_utf8_lossy(&output.stderr).trim().to_string()));
    }
    Ok(())
}

fn main() {
    let args = Args::parse();

    // Set up logging
    fern::Dispatch::new()
        .format(|out, message, record| out.finish(format_args!("{}: {}", record.level(), message)))
        .level(args.verbose.log_level_filter())
        .chain(std::io::stderr())
        .apply()
        .unwrap();

    // Route lookups go over netlink, on a single-threaded runtime that only runs while a lookup is waiting
    let runtime = tokio::runtime::Builder::new_current_thread().enable_io().build().expect("Failed to start the async runtime");
    let netlink = runtime
        .block_on(async {
            let (connection, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);
            Ok::<_, std::io::Error>(handle)
        })
        .expect("Failed to open a netlink connection");

    // Each peer's interface, kept once found so it stays restricted while its route is briefly gone (like a tunnel flapping)
    let mut peer_interfaces: BTreeMap<String, String> = BTreeMap::new();
    let mut ebgp_peers: BTreeMap<String, bool> = BTreeMap::new();
    let mut interface_indexes: BTreeMap<String, u32> = BTreeMap::new();
    let mut link_prefixes: BTreeMap<String, Vec<Prefix>> = BTreeMap::new();
    let mut refused_peers: BTreeSet<String> = BTreeSet::new();
    let mut resolution_errors: BTreeMap<String, String> = BTreeMap::new();
    let mut exports: BTreeMap<String, BTreeSet<Prefix>> = BTreeMap::new();
    let mut applied_exports = None;
    loop {
        let mut bird = bird::BirdClient::connect(&args.bird_socket)
            .map_err(|error| log::warn!("Couldn't reach Bird, so nothing changes: {}", error))
            .ok();

        // iBGP sessions are this AS's own backbone, so they're never restricted. A session is only acted on once Bird confirms it's eBGP,
        // and Bird being unreachable keeps what it said last
        if let Some(bird) = bird.as_mut() {
            for (protocol, _) in &args.peers {
                match bird.session(protocol) {
                    Ok(session) if session.local_as == session.neighbor_as => {
                        if refused_peers.insert(protocol.clone()) {
                            log::warn!("Refusing to enforce {}, since it's an iBGP session (AS{})", protocol, session.local_as);
                        }
                        ebgp_peers.remove(protocol);
                        peer_interfaces.remove(protocol);
                    }
                    Ok(session) => {
                        refused_peers.remove(protocol);
                        ebgp_peers.insert(protocol.clone(), session.multihop);
                    }
                    Err(error) => log::warn!("Couldn't check whether {} is eBGP: {}", protocol, error),
                }
            }
        }

        // Find each eBGP peer's interface, logging only when a lookup's outcome changes
        for (protocol, address) in &args.peers {
            let Some(&multihop) = ebgp_peers.get(protocol) else { continue };
            match runtime.block_on(neighbor_interface(&netlink, *address, multihop)) {
                Ok((interface, interface_index)) => {
                    if peer_interfaces.get(protocol) != Some(&interface) {
                        log::info!("{} ({}) is reached over {}", protocol, address, interface);
                    }
                    resolution_errors.remove(protocol);
                    interface_indexes.insert(interface.clone(), interface_index);
                    peer_interfaces.insert(protocol.clone(), interface);
                }
                Err(error) => {
                    if resolution_errors.get(protocol) != Some(&error) {
                        log::warn!("Can't find {}'s interface, since {} {}", protocol, address, error);
                    }
                    resolution_errors.insert(protocol.clone(), error);
                }
            }
        }

        // Each enforced interface's own subnets, keeping the last ones found if a lookup fails
        for interface in peer_interfaces.values().collect::<BTreeSet<_>>() {
            match runtime.block_on(connected_prefixes(&netlink, interface_indexes[interface])) {
                Ok(prefixes) => {
                    link_prefixes.insert(interface.clone(), prefixes);
                }
                Err(error) => log::warn!("Couldn't list {}'s subnets: {}", interface, error),
            }
        }

        // Print what would be enforced right now, for checking against a live Bird
        if args.dry_run {
            match bird.as_mut() {
                Some(bird) => print!("{}", render_ruleset(&read_exports(bird, &peer_interfaces, &link_prefixes))),
                None => std::process::exit(1),
            }
            return;
        }

        // A newly found interface allows nothing until Bird answers, and Bird being unreachable (like while it restarts) otherwise keeps
        // whatever was last enforced
        for interface in peer_interfaces.values() {
            exports.entry(interface.clone()).or_default();
        }
        if let Some(bird) = bird.as_mut() {
            exports = read_exports(bird, &peer_interfaces, &link_prefixes);
        }

        // Reapplying when the table is missing also restores it after the firewall reloads, which flushes every table
        if applied_exports.as_ref() != Some(&exports) || !table_exists() {
            match apply_ruleset(&render_ruleset(&exports)) {
                Ok(()) => {
                    for (interface, prefixes) in &exports {
                        let prefix_list = prefixes.iter().map(Prefix::to_string).collect::<Vec<_>>().join(", ");
                        log::info!("Traffic in on {} may reach: {}", interface, if prefix_list.is_empty() { "nothing" } else { &prefix_list });
                    }
                    applied_exports = Some(exports.clone());
                }
                Err(error) => log::error!("Couldn't update the firewall: {}", error),
            }
        }
        std::thread::sleep(Duration::from_secs(args.interval));
    }
}
