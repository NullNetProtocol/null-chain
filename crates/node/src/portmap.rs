//! Automatic port mapping on the local router, so a node behind a home NAT
//! can accept peers without manual port forwarding.
//!
//! PCP and NAT-PMP are tried first (one UDP exchange with the default
//! gateway), then `UPnP` IGD (SSDP multicast, then SOAP over HTTP). IPv4
//! only: IPv6 hosts usually have a public address of their own, which
//! the node already announces. The mapping is renewed before
//! its lease ends and removed when the node stops.
//!
//! Only the mapped external endpoint is reported to the node loop; it is
//! announced like an explicit `advertise`, and only when it is public.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::time::Duration;

use crab_nat::{InternetProtocol, PortMapping, PortMappingOptions, PortMappingType, TimeoutConfig};
use igd_next::aio::tokio::Tokio;
use igd_next::aio::Gateway;
use igd_next::{AddAnyPortError, AddPortError, PortMappingProtocol, SearchOptions};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::Network;
use crate::discovery;
use crate::node::Event;

/// Lease asked of the router, in seconds. Renewed at half of what the
/// router grants, so a node that crashes leaves a mapping for at most
/// this long on routers that honour leases.
const LEASE_SECONDS: u32 = 3_600;
/// Wait before searching again for a mapping that could not be renewed.
const LOST_RETRY_SECONDS: u64 = 60;
/// Wait before searching again after no router mapped the port. Long,
/// since most routers that refuse once refuse until reconfigured, and a
/// short loop would multicast SSDP on the LAN all day.
const RETRY_SECONDS: u64 = 1_800;
/// Longest one search or renewal may take. The `UPnP` library sets no HTTP
/// timeout of its own, so a router that accepts the connection and never
/// answers would otherwise stall the mapping forever.
const STEP_SECONDS: u64 = 30;
/// Time a stopping node gives the router to delete the mapping.
const REMOVE_SECONDS: u64 = 3;
/// How long `UPnP` discovery waits for a router to answer.
const SSDP_SECONDS: u64 = 5;
/// First PCP/NAT-PMP reply timeout; doubled on each of [`PMP_RETRIES`].
/// A router without either protocol then costs under two seconds.
const PMP_FIRST_TIMEOUT_MILLIS: u64 = 250;
/// PCP/NAT-PMP retries after the first request.
const PMP_RETRIES: usize = 2;
/// What the router's mapping table shows for this node.
const DESCRIPTION: &str = "NULL node";
/// Where `UPnP` routers listen for discovery.
const SSDP_MULTICAST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);

/// Which protocol mapped the port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Port Control Protocol (RFC 6887).
    Pcp,
    /// NAT Port Mapping Protocol (RFC 6886).
    NatPmp,
    /// `UPnP` Internet Gateway Device.
    Upnp,
}

impl core::fmt::Display for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Pcp => "PCP",
            Self::NatPmp => "NAT-PMP",
            Self::Upnp => "UPnP",
        })
    }
}

/// Where automatic port mapping stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MappingState {
    /// Looking for a router that maps ports.
    Searching,
    /// The router forwards `external` to this node's listener.
    Mapped {
        /// The protocol that mapped it.
        protocol: Protocol,
        /// The router's public address and the port it forwards.
        external: SocketAddr,
    },
    /// The router mapped the port, but its own external address is not a
    /// public one: another NAT sits behind it, such as an ISP's
    /// carrier-grade NAT. Other nodes still cannot reach this one, so the
    /// endpoint is not announced.
    NotPublic {
        /// The protocol that mapped it.
        protocol: Protocol,
        /// The non-public address the router reported.
        external: SocketAddr,
    },
    /// No router mapped the port; the reason, for the user.
    Failed(String),
}

impl MappingState {
    /// The endpoint to announce to peers, if there is one.
    pub fn announced(&self) -> Option<SocketAddr> {
        match self {
            Self::Mapped { external, .. } => Some(*external),
            _ => None,
        }
    }

    /// The state for a mapping the router reported at `external`.
    fn classify(protocol: Protocol, external: SocketAddr, network: Network) -> Self {
        if discovery::allowed(external, network) {
            Self::Mapped { protocol, external }
        } else {
            Self::NotPublic { protocol, external }
        }
    }
}

/// Why a mapping attempt failed.
#[derive(Debug, Error)]
pub enum MapError {
    /// No PCP/NAT-PMP gateway answered and no `UPnP` router was found.
    #[error("no router answered (PCP/NAT-PMP: {pmp}; UPnP: {upnp})")]
    NoRouter {
        /// Why PCP/NAT-PMP failed.
        pmp: String,
        /// Why `UPnP` failed.
        upnp: String,
    },
    /// The router that mapped the port refused a later request.
    #[error("{0}: {1}")]
    Router(Protocol, String),
    /// The router did not answer one search or renewal within 30 seconds.
    #[error("the router did not answer in time")]
    Timeout,
    /// The local address towards the router could not be found.
    #[error("no local address towards the router: {0}")]
    Local(#[from] std::io::Error),
}

/// Where to look for routers. Production uses [`Routers::system`]; tests
/// point both at fakes on loopback.
#[derive(Clone, Copy, Debug)]
pub struct Routers {
    /// The PCP/NAT-PMP gateway, normally the default route's next hop.
    pub pmp: Option<IpAddr>,
    /// Where `UPnP` discovery requests go.
    pub ssdp: SocketAddr,
}

impl Routers {
    /// The default gateway and the standard SSDP multicast group.
    pub async fn system() -> Self {
        let pmp = tokio::task::spawn_blocking(default_gateway)
            .await
            .ok()
            .flatten();
        Self {
            pmp,
            ssdp: SSDP_MULTICAST,
        }
    }
}

/// The IPv4 default gateway, if the system reports one.
fn default_gateway() -> Option<IpAddr> {
    let gateway = netdev::get_default_gateway().ok()?;
    gateway.ipv4.first().copied().map(IpAddr::V4)
}

/// The local address this host uses to reach `router`, which is what a
/// router needs as the mapping's internal client. Connecting a UDP socket
/// picks the route without sending anything.
fn local_ip_towards(router: IpAddr) -> std::io::Result<IpAddr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((router, crab_nat::GATEWAY_PORT))?;
    Ok(socket.local_addr()?.ip())
}

/// Seconds until a mapping granted for `lifetime` seconds is renewed: at
/// half the lease, so even a router granting a short lease gets the
/// renewal before the mapping expires, and never in the same second.
/// A permanent lease (`0`) is refreshed as if it had the requested one,
/// so a router that rebooted and forgot it gets it back.
fn renew_after(lifetime: u32) -> Duration {
    let lease = if lifetime == 0 {
        LEASE_SECONDS
    } else {
        lifetime
    };
    Duration::from_secs((u64::from(lease) / 2).max(1))
}

/// A mapping held on a router.
enum Active {
    /// Through PCP or NAT-PMP.
    Pmp(PortMapping),
    /// Through `UPnP`.
    Upnp(UpnpMapping),
}

/// A `UPnP` mapping and what renewing it needs.
struct UpnpMapping {
    gateway: Gateway<Tokio>,
    local: SocketAddr,
    external_port: u16,
    lease: u32,
}

impl Active {
    fn protocol(&self) -> Protocol {
        match self {
            Self::Pmp(mapping) => pmp_protocol(mapping),
            Self::Upnp(_) => Protocol::Upnp,
        }
    }

    fn renew_after(&self) -> Duration {
        match self {
            Self::Pmp(mapping) => renew_after(mapping.lifetime()),
            Self::Upnp(mapping) => renew_after(mapping.lease),
        }
    }

    /// The router's external address and the mapped port. Asked again on
    /// every renewal: the ISP may have handed the router a new address.
    async fn external(&self) -> Result<SocketAddr, MapError> {
        let protocol = self.protocol();
        let refused = |e: String| MapError::Router(protocol, e);
        match self {
            Self::Pmp(mapping) => {
                let ip = match mapping.mapping_type() {
                    PortMappingType::Pcp { external_ip, .. } => external_ip,
                    PortMappingType::NatPmp => IpAddr::V4(
                        crab_nat::natpmp::external_address(mapping.gateway(), Some(pmp_timeouts()))
                            .await
                            .map_err(|e| refused(e.to_string()))?,
                    ),
                };
                Ok(SocketAddr::new(ip, mapping.external_port().get()))
            }
            Self::Upnp(mapping) => {
                let ip = mapping
                    .gateway
                    .get_external_ip()
                    .await
                    .map_err(|e| refused(e.to_string()))?;
                Ok(SocketAddr::new(ip, mapping.external_port))
            }
        }
    }

    async fn renew(&mut self) -> Result<(), MapError> {
        let protocol = self.protocol();
        match self {
            Self::Pmp(mapping) => mapping
                .renew()
                .await
                .map_err(|e| MapError::Router(protocol, e.to_string())),
            Self::Upnp(mapping) => mapping
                .gateway
                .add_port(
                    PortMappingProtocol::TCP,
                    mapping.external_port,
                    mapping.local,
                    mapping.lease,
                    DESCRIPTION,
                )
                .await
                .map_err(|e| MapError::Router(protocol, e.to_string())),
        }
    }

    /// Deletes the mapping, giving the router [`REMOVE_SECONDS`].
    async fn remove(self) {
        let removal = async {
            match self {
                Self::Pmp(mapping) => mapping.try_drop().await.map_err(|(e, _)| e.to_string()),
                Self::Upnp(mapping) => mapping
                    .gateway
                    .remove_port(PortMappingProtocol::TCP, mapping.external_port)
                    .await
                    .map_err(|e| e.to_string()),
            }
        };
        match tokio::time::timeout(Duration::from_secs(REMOVE_SECONDS), removal).await {
            Ok(Ok(())) => crate::logging::info("port mapping removed"),
            Ok(Err(error)) => {
                crate::logging::warn(&format!("removing the port mapping failed: {error}"));
            }
            Err(_) => crate::logging::warn("removing the port mapping timed out"),
        }
    }
}

fn pmp_protocol(mapping: &PortMapping) -> Protocol {
    match mapping.mapping_type() {
        PortMappingType::Pcp { .. } => Protocol::Pcp,
        PortMappingType::NatPmp => Protocol::NatPmp,
    }
}

fn pmp_timeouts() -> TimeoutConfig {
    TimeoutConfig {
        initial_timeout: Duration::from_millis(PMP_FIRST_TIMEOUT_MILLIS),
        max_retries: PMP_RETRIES,
        max_retry_timeout: None,
    }
}

/// Maps `port` through PCP, falling back to NAT-PMP, on `gateway`.
async fn map_pmp(gateway: IpAddr, port: NonZeroU16) -> Result<Active, String> {
    let client = local_ip_towards(gateway).map_err(|e| e.to_string())?;
    let options = PortMappingOptions {
        external_port: Some(port),
        lifetime_seconds: Some(LEASE_SECONDS),
        timeout_config: Some(pmp_timeouts()),
    };
    PortMapping::new(gateway.into(), client, InternetProtocol::Tcp, port, options)
        .await
        .map(Active::Pmp)
        .map_err(|e| e.to_string())
}

/// Maps `port` through the first `UPnP` router answering at `ssdp`: the
/// same external port if free, else any the router picks. Routers that
/// only keep permanent mappings get one, removed again at shutdown.
async fn map_upnp(ssdp: SocketAddr, port: NonZeroU16) -> Result<Active, String> {
    let options = SearchOptions {
        broadcast_address: ssdp,
        timeout: Some(Duration::from_secs(SSDP_SECONDS)),
        ..SearchOptions::default()
    };
    let gateway = igd_next::aio::tokio::search_gateway(options)
        .await
        .map_err(|e| e.to_string())?;
    let local = SocketAddr::new(
        local_ip_towards(gateway.addr.ip()).map_err(|e| e.to_string())?,
        port.get(),
    );
    let mut mapping = UpnpMapping {
        gateway,
        local,
        external_port: port.get(),
        lease: LEASE_SECONDS,
    };
    let added = match add_same_port(&mapping).await {
        Err(AddPortError::OnlyPermanentLeasesSupported) => {
            mapping.lease = 0;
            add_same_port(&mapping).await
        }
        other => other,
    };
    match added {
        Ok(()) => {}
        Err(AddPortError::PortInUse) => {
            mapping.external_port = add_any_port(&mut mapping).await?;
        }
        Err(error) => return Err(error.to_string()),
    }
    Ok(Active::Upnp(mapping))
}

async fn add_same_port(mapping: &UpnpMapping) -> Result<(), AddPortError> {
    mapping
        .gateway
        .add_port(
            PortMappingProtocol::TCP,
            mapping.external_port,
            mapping.local,
            mapping.lease,
            DESCRIPTION,
        )
        .await
}

/// Lets the router choose the external port, for when ours is taken.
async fn add_any_port(mapping: &mut UpnpMapping) -> Result<u16, String> {
    let add = |lease| {
        mapping
            .gateway
            .add_any_port(PortMappingProtocol::TCP, mapping.local, lease, DESCRIPTION)
    };
    match add(mapping.lease).await {
        Err(AddAnyPortError::OnlyPermanentLeasesSupported) => {
            let port = add(0).await.map_err(|e| e.to_string())?;
            mapping.lease = 0;
            Ok(port)
        }
        other => other.map_err(|e| e.to_string()),
    }
}

/// Maps `port` with the first protocol a router accepts.
async fn establish(routers: Routers, port: NonZeroU16) -> Result<Active, MapError> {
    let pmp = match routers.pmp {
        Some(gateway) => match map_pmp(gateway, port).await {
            Ok(active) => return Ok(active),
            Err(error) => error,
        },
        None => "no default gateway".into(),
    };
    map_upnp(routers.ssdp, port)
        .await
        .map_err(|upnp| MapError::NoRouter { pmp, upnp })
}

/// Holds a mapping until stopped: maps, reports, renews, and after a
/// failure searches again later. A failed renewal (the router rebooted,
/// or the network changed) leads to a fresh search a minute later.
struct Mapper {
    routers: Routers,
    port: NonZeroU16,
    network: Network,
    events: mpsc::Sender<Event>,
    last: Option<MappingState>,
}

impl Mapper {
    /// Sends `state` to the node loop if it changed.
    async fn report(&mut self, state: MappingState) {
        if self.last.as_ref() == Some(&state) {
            return;
        }
        match &state {
            MappingState::Searching => {}
            MappingState::Mapped { protocol, external } => crate::logging::info(&format!(
                "port mapping: {protocol} forwards {external} to port {}",
                self.port
            )),
            MappingState::NotPublic { protocol, external } => crate::logging::warn(&format!(
                "port mapping: {protocol} mapped the port, but the router's address {} \
                 is not public (carrier-grade NAT?); not announcing it",
                external.ip()
            )),
            MappingState::Failed(reason) => {
                crate::logging::info(&format!("port mapping: {reason}"));
            }
        }
        self.last = Some(state.clone());
        let _ = self.events.send(Event::PortMapping(state)).await;
    }

    /// One step: renews or establishes the mapping in `held` and reports
    /// the result. Returns how long to wait before the next. A mapping
    /// that cannot be renewed or read is removed and reported failed, so
    /// its endpoint is no longer announced; a lost one is searched
    /// for again after [`LOST_RETRY_SECONDS`], and a search that finds
    /// nothing waits [`RETRY_SECONDS`].
    async fn step(&mut self, held: &mut Option<Active>) -> Duration {
        let renewing = held.is_some();
        let attempt = tokio::time::timeout(Duration::from_secs(STEP_SECONDS), self.attempt(held))
            .await
            .unwrap_or(Err(MapError::Timeout));
        let error = match attempt {
            Ok((protocol, external, wait)) => {
                let state = MappingState::classify(protocol, external, self.network);
                self.report(state).await;
                return wait;
            }
            Err(error) => error,
        };
        if let Some(active) = held.take() {
            active.remove().await;
        }
        // Reported either way, so the node stops announcing a lost endpoint.
        self.report(MappingState::Failed(error.to_string())).await;
        if renewing {
            crate::logging::warn(&format!("port mapping lost: {error}"));
            Duration::from_secs(LOST_RETRY_SECONDS)
        } else {
            Duration::from_secs(RETRY_SECONDS)
        }
    }

    /// Renews the mapping in `held`, or makes one and keeps it there, and
    /// reads the external endpoint. The mapping stays in `held` while the
    /// router is asked, so a cancelled attempt still leaves it to remove.
    async fn attempt(
        &mut self,
        held: &mut Option<Active>,
    ) -> Result<(Protocol, SocketAddr, Duration), MapError> {
        let active = if let Some(active) = held {
            active.renew().await?;
            active
        } else {
            self.report(MappingState::Searching).await;
            held.insert(establish(self.routers, self.port).await?)
        };
        let external = active.external().await?;
        Ok((active.protocol(), external, active.renew_after()))
    }

    /// Steps until `stop`, then removes the mapping. A stop during a step
    /// gives the router [`REMOVE_SECONDS`] to finish it, so a mapping it
    /// was making is held and removed too, without holding up shutdown
    /// on a slow router.
    async fn run(mut self, mut stop: oneshot::Receiver<()>) {
        let mut held = None;
        loop {
            let wait = {
                let stepping = self.step(&mut held);
                tokio::pin!(stepping);
                tokio::select! {
                    wait = &mut stepping => Some(wait),
                    _ = &mut stop => {
                        let grace = Duration::from_secs(REMOVE_SECONDS);
                        let _ = tokio::time::timeout(grace, stepping).await;
                        None
                    }
                }
            };
            let Some(wait) = wait else { break };
            tokio::select! {
                _ = &mut stop => break,
                () = tokio::time::sleep(wait) => {}
            }
        }
        if let Some(active) = held {
            active.remove().await;
        }
    }
}

/// A running mapping task. [`Task::stop`] removes the mapping.
pub struct Task {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

impl Task {
    /// Starts mapping `port` on the routers in `routers` and reporting
    /// to the node loop through `events`.
    pub fn spawn(
        routers: Routers,
        port: NonZeroU16,
        network: Network,
        events: mpsc::Sender<Event>,
    ) -> Self {
        let (stop, stopped) = oneshot::channel();
        let mapper = Mapper {
            routers,
            port,
            network,
            events,
            last: None,
        };
        Self {
            stop,
            join: tokio::spawn(mapper.run(stopped)),
        }
    }

    /// Removes the mapping and waits for the task: the grace a step in
    /// progress gets, the removal, and a margin.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        let wait = Duration::from_secs(REMOVE_SECONDS.saturating_mul(3));
        if tokio::time::timeout(wait, self.join).await.is_err() {
            crate::logging::warn("port mapping did not stop in time");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_public_mapped_endpoints_are_announced_on_mainnet() {
        let public = socket("8.8.8.8:19000");
        let cgnat = socket("100.64.1.2:19000");
        let mapped = MappingState::classify(Protocol::Upnp, public, Network::Main);
        assert_eq!(mapped.announced(), Some(public));
        let behind = MappingState::classify(Protocol::NatPmp, cgnat, Network::Main);
        assert_eq!(
            behind,
            MappingState::NotPublic {
                protocol: Protocol::NatPmp,
                external: cgnat
            }
        );
        assert_eq!(behind.announced(), None);
        assert_eq!(
            MappingState::classify(Protocol::Pcp, cgnat, Network::Test).announced(),
            Some(cgnat)
        );
        assert_eq!(MappingState::Searching.announced(), None);
        assert_eq!(MappingState::Failed("x".into()).announced(), None);
    }

    #[test]
    fn mappings_renew_at_half_their_lease_even_when_it_is_short() {
        assert_eq!(renew_after(7_200), Duration::from_secs(3_600));
        assert_eq!(renew_after(10), Duration::from_secs(5));
        assert_eq!(renew_after(1), Duration::from_secs(1));
        assert_eq!(
            renew_after(0),
            Duration::from_secs(u64::from(LEASE_SECONDS) / 2)
        );
    }

    #[test]
    fn the_local_address_towards_a_router_is_on_its_route() {
        let local = local_ip_towards(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert!(local.is_loopback(), "{local}");
    }

    #[test]
    fn protocols_are_named_as_users_know_them() {
        assert_eq!(Protocol::Pcp.to_string(), "PCP");
        assert_eq!(Protocol::NatPmp.to_string(), "NAT-PMP");
        assert_eq!(Protocol::Upnp.to_string(), "UPnP");
    }

    /// Waits for the mapper's next report.
    async fn next_state(events: &mut mpsc::Receiver<Event>) -> MappingState {
        let event = tokio::time::timeout(Duration::from_secs(30), events.recv())
            .await
            .unwrap()
            .unwrap();
        match event {
            Event::PortMapping(state) => state,
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Where no router listens: discovery there finds nothing.
    async fn silent() -> (tokio::net::UdpSocket, SocketAddr) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        (socket, addr)
    }

    /// A NAT-PMP gateway on loopback that answers PCP with "unsupported
    /// version", maps every port to `external_port`, and reports each
    /// mapping request's lifetime. `None` when the port is taken.
    async fn fake_natpmp(external_port: u16) -> Option<mpsc::UnboundedReceiver<u32>> {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", crab_nat::GATEWAY_PORT))
            .await
            .ok()?;
        let (lifetimes, received) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 1100];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let epoch = [0, 0, 0, 9];
                let reply: Vec<u8> = match (buf[0], buf[1]) {
                    (2, op) => [[0, op | 0x80, 0, 1], epoch].concat(),
                    (0, 0) => [[0, 128, 0, 0], epoch, [8, 8, 4, 4]].concat(),
                    (0, 2) if n == 12 => {
                        let lifetime = u32::from_be_bytes(buf[8..12].try_into().unwrap());
                        let _ = lifetimes.send(lifetime);
                        let port = external_port.to_be_bytes();
                        [&[0, 130, 0, 0][..], &epoch, &buf[4..6], &port, &buf[8..12]].concat()
                    }
                    _ => continue,
                };
                let _ = socket.send_to(&reply, from).await;
            }
        });
        Some(received)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_natpmp_router_maps_the_port_and_the_mapping_is_removed_on_stop() {
        let Some(mut lifetimes) = fake_natpmp(19_001).await else {
            eprintln!("skipping: the NAT-PMP port is taken on this host");
            return;
        };
        let (_ssdp, ssdp) = silent().await;
        let (events, mut states) = mpsc::channel(8);
        let routers = Routers {
            pmp: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ssdp,
        };
        let task = Task::spawn(
            routers,
            NonZeroU16::new(19_000).unwrap(),
            Network::Main,
            events,
        );
        assert_eq!(next_state(&mut states).await, MappingState::Searching);
        assert_eq!(
            next_state(&mut states).await,
            MappingState::Mapped {
                protocol: Protocol::NatPmp,
                external: socket("8.8.4.4:19001"),
            }
        );
        assert_eq!(lifetimes.recv().await, Some(LEASE_SECONDS));
        task.stop().await;
        assert_eq!(lifetimes.recv().await, Some(0), "mapping not deleted");
    }

    /// SOAP actions the fake `UPnP` router answered, with their lease.
    #[derive(Debug, PartialEq, Eq)]
    enum Soap {
        Add { lease: u32, port: u16 },
        Delete { port: u16 },
    }

    /// The text between `<tag>` and `</tag>` in `body`.
    fn element<'a>(body: &'a str, tag: &str) -> &'a str {
        let (_, rest) = body.split_once(&format!("<{tag}>")).unwrap();
        rest.split_once(&format!("</{tag}>")).unwrap().0
    }

    const IGD_DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<SCPDURL>/scpd.xml</SCPDURL><controlURL>/ctl</controlURL>
</service></serviceList></device></deviceList></device></deviceList>
</device></root>"#;

    fn scpd() -> String {
        let action = |name: &str, args: &[&str]| {
            let args: Vec<String> = args
                .iter()
                .map(|a| format!("<argument><name>{a}</name><direction>in</direction></argument>"))
                .collect();
            let args = args.concat();
            format!("<action><name>{name}</name><argumentList>{args}</argumentList></action>")
        };
        format!(
            r#"<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0"><actionList>{}{}{}</actionList></scpd>"#,
            action(
                "AddPortMapping",
                &[
                    "NewRemoteHost",
                    "NewExternalPort",
                    "NewProtocol",
                    "NewInternalPort",
                    "NewInternalClient",
                    "NewEnabled",
                    "NewPortMappingDescription",
                    "NewLeaseDuration",
                ],
            ),
            action(
                "DeletePortMapping",
                &["NewRemoteHost", "NewExternalPort", "NewProtocol"]
            ),
            action("GetExternalIPAddress", &[]),
        )
    }

    fn soap(body: &str) -> String {
        format!(
            r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>{body}</s:Body></s:Envelope>"#
        )
    }

    /// How the fake `UPnP` router misbehaves beyond refusing leases.
    #[derive(Default)]
    struct Igd {
        /// An external port already mapped to another host (error 718).
        taken: Option<u16>,
        /// Never answer the external address query.
        stall_external: bool,
        /// Refuse every control request, as a router that lost its WAN.
        broken: std::sync::atomic::AtomicBool,
    }

    fn fault(code: u16, description: &str) -> String {
        soap(&format!(
            "<s:Fault><detail><UPnPError><errorCode>{code}</errorCode>\
             <errorDescription>{description}</errorDescription>\
             </UPnPError></detail></s:Fault>"
        ))
    }

    /// Answers one `UPnP` control or description request. Like some real
    /// routers, it refuses leases other than permanent (error 725).
    fn igd_reply(
        igd: &Igd,
        head: &str,
        body: &str,
        actions: &mpsc::UnboundedSender<Soap>,
    ) -> String {
        let path = head.split_whitespace().nth(1).unwrap_or_default();
        match path {
            "/desc.xml" => IGD_DESCRIPTION.into(),
            "/scpd.xml" => scpd(),
            _ if head.contains("#GetExternalIPAddress") => soap(
                r#"<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>8.8.8.8</NewExternalIPAddress></u:GetExternalIPAddressResponse>"#,
            ),
            _ if head.contains("#AddPortMapping") => {
                let lease: u32 = element(body, "NewLeaseDuration").parse().unwrap();
                let port = element(body, "NewExternalPort").parse().unwrap();
                if lease != 0 {
                    return fault(725, "OnlyPermanentLeasesSupported");
                }
                if igd.taken == Some(port) {
                    return fault(718, "ConflictInMappingEntry");
                }
                let _ = actions.send(Soap::Add { lease, port });
                soap(
                    r#"<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>"#,
                )
            }
            _ if head.contains("#DeletePortMapping") => {
                let port = element(body, "NewExternalPort").parse().unwrap();
                let _ = actions.send(Soap::Delete { port });
                soap(
                    r#"<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>"#,
                )
            }
            _ => String::new(),
        }
    }

    /// Reads one HTTP request: its head and its body.
    async fn read_http(stream: &mut tokio::net::TcpStream) -> (String, String) {
        use tokio::io::AsyncReadExt;
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            data.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&data).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if body.len() >= length || n == 0 {
                    return (head.to_owned(), body.to_owned());
                }
            } else if n == 0 {
                return (text, String::new());
            }
        }
    }

    /// A `UPnP` router on loopback: an SSDP responder pointing at an HTTP
    /// server for descriptions and SOAP. Returns the SSDP address.
    async fn fake_igd(igd: Igd, actions: mpsc::UnboundedSender<Soap>) -> SocketAddr {
        fake_shared_igd(std::sync::Arc::new(igd), actions).await
    }

    /// [`fake_igd`], with the router kept by the test to change later.
    async fn fake_shared_igd(
        igd: std::sync::Arc<Igd>,
        actions: mpsc::UnboundedSender<Soap>,
    ) -> SocketAddr {
        use tokio::io::AsyncWriteExt;
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let location = format!("http://{}/desc.xml", http.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = http.accept().await {
                let actions = actions.clone();
                let igd = igd.clone();
                tokio::spawn(async move {
                    let (head, body) = read_http(&mut stream).await;
                    if igd.stall_external && head.contains("#GetExternalIPAddress") {
                        std::future::pending::<()>().await;
                    }
                    let reply = if igd.broken.load(std::sync::atomic::Ordering::SeqCst)
                        && head.starts_with("POST")
                    {
                        fault(501, "ActionFailed")
                    } else {
                        igd_reply(&igd, &head, &body, &actions)
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                        reply.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let ssdp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = ssdp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((_, from)) = ssdp.recv_from(&mut buf).await {
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\
                     ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                     USN: uuid:fake::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                     LOCATION: {location}\r\n\r\n"
                );
                let _ = ssdp.send_to(reply.as_bytes(), from).await;
            }
        });
        addr
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_upnp_router_with_permanent_leases_only_maps_and_unmaps_the_port() {
        let (actions, mut answered) = mpsc::unbounded_channel();
        let ssdp = fake_igd(Igd::default(), actions).await;
        let (events, mut states) = mpsc::channel(8);
        let routers = Routers { pmp: None, ssdp };
        let task = Task::spawn(
            routers,
            NonZeroU16::new(19_000).unwrap(),
            Network::Main,
            events,
        );
        assert_eq!(next_state(&mut states).await, MappingState::Searching);
        assert_eq!(
            next_state(&mut states).await,
            MappingState::Mapped {
                protocol: Protocol::Upnp,
                external: socket("8.8.8.8:19000"),
            }
        );
        assert_eq!(
            answered.recv().await,
            Some(Soap::Add {
                lease: 0,
                port: 19_000
            })
        );
        task.stop().await;
        assert_eq!(answered.recv().await, Some(Soap::Delete { port: 19_000 }));
    }

    /// Starts mapping port 19000 through the fake `UPnP` router at `ssdp`.
    fn map_through(ssdp: SocketAddr) -> (Task, mpsc::Receiver<Event>) {
        let (events, states) = mpsc::channel(8);
        let routers = Routers { pmp: None, ssdp };
        let port = NonZeroU16::new(19_000).unwrap();
        (Task::spawn(routers, port, Network::Main, events), states)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_permanent_only_router_with_our_port_taken_maps_another() {
        let (actions, mut answered) = mpsc::unbounded_channel();
        let igd = Igd {
            taken: Some(19_000),
            ..Igd::default()
        };
        let (task, mut states) = map_through(fake_igd(igd, actions).await);
        assert_eq!(next_state(&mut states).await, MappingState::Searching);
        let Some(Soap::Add { lease: 0, port }) = answered.recv().await else {
            panic!("expected a permanent mapping");
        };
        assert_ne!(port, 19_000);
        assert_eq!(
            next_state(&mut states).await,
            MappingState::Mapped {
                protocol: Protocol::Upnp,
                external: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), port),
            }
        );
        task.stop().await;
        assert_eq!(answered.recv().await, Some(Soap::Delete { port }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_while_the_router_is_still_answering_removes_the_mapping() {
        let (actions, mut answered) = mpsc::unbounded_channel();
        let igd = Igd {
            stall_external: true,
            ..Igd::default()
        };
        let (task, mut states) = map_through(fake_igd(igd, actions).await);
        assert_eq!(next_state(&mut states).await, MappingState::Searching);
        assert_eq!(
            answered.recv().await,
            Some(Soap::Add {
                lease: 0,
                port: 19_000
            })
        );
        task.stop().await;
        assert_eq!(answered.recv().await, Some(Soap::Delete { port: 19_000 }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_mapping_that_cannot_be_renewed_is_reported_failed_at_once() {
        let (actions, _answered) = mpsc::unbounded_channel();
        let igd = std::sync::Arc::new(Igd::default());
        let ssdp = fake_shared_igd(igd.clone(), actions).await;
        let (events, mut states) = mpsc::channel(8);
        let mut mapper = Mapper {
            routers: Routers { pmp: None, ssdp },
            port: NonZeroU16::new(19_000).unwrap(),
            network: Network::Main,
            events,
            last: None,
        };
        let mut held = None;
        mapper.step(&mut held).await;
        assert_eq!(next_state(&mut states).await, MappingState::Searching);
        assert!(next_state(&mut states).await.announced().is_some());
        igd.broken.store(true, std::sync::atomic::Ordering::SeqCst);
        let wait = mapper.step(&mut held).await;
        assert_eq!(wait, Duration::from_secs(LOST_RETRY_SECONDS));
        assert!(held.is_none(), "the lost mapping is dropped");
        let MappingState::Failed(reason) = next_state(&mut states).await else {
            panic!("a lost mapping must stop being announced");
        };
        assert!(reason.contains("UPnP"), "{reason}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_any_router_the_mapping_fails_with_both_reasons() {
        let (_ssdp, ssdp) = silent().await;
        let (events, mut states) = mpsc::channel(8);
        let routers = Routers { pmp: None, ssdp };
        let task = Task::spawn(
            routers,
            NonZeroU16::new(19_000).unwrap(),
            Network::Main,
            events,
        );
        assert_eq!(next_state(&mut states).await, MappingState::Searching);
        let MappingState::Failed(reason) = next_state(&mut states).await else {
            panic!("expected a failure");
        };
        assert!(reason.contains("no default gateway"), "{reason}");
        assert!(reason.contains("UPnP"), "{reason}");
        task.stop().await;
    }
}
