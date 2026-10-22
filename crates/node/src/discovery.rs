//! Address announcement policy. Mainnet gossip only contains public endpoints;
//! local endpoints remain usable through explicit configuration and on testnet.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use null_p2p::peer::Direction;
use socket2::SockRef;
use tokio::net::TcpListener;

use crate::config::{Config, Network};
use crate::{Error, Result};

/// Time between address exchanges on established connections, in seconds.
pub(crate) const EXCHANGE_SECONDS: u64 = 600;
/// Addresses returned by one exchange.
pub(crate) const SAMPLE_SIZE: usize = 100;
/// Minimum seconds (node ticks) between address-list replies to one peer.
pub(crate) const REPLY_SECONDS: u64 = 60;
/// Addresses accepted from an outbound peer per exchange: its reply to our
/// `GetAddr` plus its own announcement.
pub(crate) const OUTBOUND_ADDR_ALLOWANCE: usize = SAMPLE_SIZE + 1;
/// Addresses accepted from an inbound peer per exchange: only its own
/// announcement. Inbound connections cost an attacker nothing, so they are
/// never asked for, nor trusted with, address lists.
pub(crate) const INBOUND_ADDR_ALLOWANCE: usize = 1;
/// Extra outbound connection used to verify gossip when regular slots are full.
pub(crate) const MAX_PROBES: usize = 1;

/// Gossiped addresses a peer in `direction` may send per exchange period.
pub(crate) fn addr_allowance(direction: Direction) -> usize {
    match direction {
        Direction::Outbound => OUTBOUND_ADDR_ALLOWANCE,
        Direction::Inbound => INBOUND_ADDR_ALLOWANCE,
    }
}

/// Checks the announcement settings: an explicit `advertise` needs a
/// reachable address, a listener with inbound slots and a direct transport.
///
/// # Errors
/// [`Error::Argument`] naming the conflicting setting.
pub(crate) fn validate(config: &Config) -> Result<()> {
    if let Some(addr) = config.advertise {
        if config.listen.is_none()
            || config.max_inbound == 0
            || config.proxy.is_some()
            || config.i2p.is_some()
            || !allowed(addr, config.network)
        {
            return Err(Error::Argument(
                "advertise requires a reachable IP:port, a listener with inbound slots, and no proxy or I2P".into(),
            ));
        }
    }
    Ok(())
}

/// Whether a bound listener also accepts IPv4 connections. An IPv6
/// wildcard does only when the socket is dual-stack, which is not a safe
/// default to assume: Windows and the BSDs make `[::]` IPv6-only, and Linux
/// follows the `net.ipv6.bindv6only` sysctl. So the socket is asked.
pub(crate) fn accepts_ipv4(listener: &TcpListener) -> bool {
    match listener.local_addr() {
        Ok(SocketAddr::V4(_)) => true,
        Ok(SocketAddr::V6(addr)) => {
            addr.ip().is_unspecified() && matches!(SockRef::from(listener).only_v6(), Ok(false))
        }
        Err(_) => false,
    }
}

/// Endpoint to announce over a direct connection. A wildcard listener uses
/// the interface selected for this connection, when the listener accepts
/// that family (see [`accepts_ipv4`]); NAT needs an explicit override.
pub(crate) fn announcement(
    listen: Option<SocketAddr>,
    advertise: Option<SocketAddr>,
    local: Option<SocketAddr>,
    network: Network,
    private_transport: bool,
    listen_accepts_ipv4: bool,
) -> Option<SocketAddr> {
    if private_transport {
        return None;
    }
    let listen = listen?;
    let addr = advertise.or_else(|| {
        let ip = if listen.ip().is_unspecified() {
            let local = local?;
            let ip = local.ip().to_canonical();
            // An outbound route in one family does not make the listener
            // reachable in it: an IPv4 listener never takes IPv6, and an
            // IPv6 one takes IPv4 only when dual-stack. Explicit NAT
            // mappings can still override the family through `advertise`.
            let reachable = if ip.is_ipv4() {
                listen_accepts_ipv4
            } else {
                listen.is_ipv6()
            };
            if !reachable {
                return None;
            }
            ip
        } else {
            listen.ip()
        };
        Some(SocketAddr::new(ip, listen.port()))
    })?;
    allowed(addr, network).then_some(addr)
}

pub(crate) fn allowed(addr: SocketAddr, network: Network) -> bool {
    let ip = match addr.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip @ IpAddr::V4(_) => ip,
    };
    if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => !ip.is_broadcast() && (network == Network::Test || public_v4(ip)),
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            network == Network::Test
                || ((a & 0xe000) == 0x2000
                    && !(a == 0x2001 && (b < 0x0200 || b == 0x0db8))
                    && a != 0x2002
                    && !(a == 0x3fff && b < 0x1000))
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_documentation()
        && a != 0
        && a < 224
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 198 && (18..=19).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mainnet_gossip_rejects_local_special_and_invalid_endpoints() {
        for ip in [
            "0.0.0.0:1",
            "0.1.2.3:1",
            "127.0.0.1:1",
            "10.0.0.1:1",
            "172.16.0.1:1",
            "192.168.1.1:1",
            "169.254.1.1:1",
            "100.64.0.1:1",
            "192.0.0.1:1",
            "192.0.2.1:1",
            "198.18.0.1:1",
            "224.0.0.1:1",
            "240.0.0.1:1",
            "255.255.255.255:1",
            "8.8.8.8:0",
            "[::]:1",
            "[::1]:1",
            "[::ffff:127.0.0.1]:1",
            "[fc00::1]:1",
            "[fe80::1]:1",
            "[ff02::1]:1",
            "[2001:db8::1]:1",
            "[2002:7f00:1::]:1",
        ] {
            assert!(!allowed(socket(ip), Network::Main), "{ip}");
        }
        for ip in [
            "8.8.8.8:19000",
            "[2606:4700::1111]:19000",
            "[::ffff:8.8.8.8]:19000",
        ] {
            assert!(allowed(socket(ip), Network::Main), "{ip}");
        }
        assert!(allowed(socket("127.0.0.1:19000"), Network::Test));
        assert!(!allowed(socket("0.0.0.0:19000"), Network::Test));
    }

    #[test]
    fn announcements_use_listener_ports_and_respect_transport_privacy() {
        let bound = Some(socket("0.0.0.0:19000"));
        let local = Some(socket("8.8.8.8:54321"));
        let public = Some(socket("8.8.8.8:19000"));
        assert_eq!(
            announcement(bound, None, local, Network::Main, false, true),
            public
        );
        assert_eq!(
            announcement(
                bound,
                None,
                Some(socket("[2606:4700::1111]:54321")),
                Network::Main,
                false,
                true
            ),
            None
        );
        assert_eq!(
            announcement(bound, None, local, Network::Main, true, true),
            None
        );
        for ipv4_local in [local, Some(socket("[::ffff:8.8.8.8]:54321"))] {
            for (dual_stack, expected) in [(true, public), (false, None)] {
                assert_eq!(
                    announcement(
                        Some(socket("[::]:19000")),
                        None,
                        ipv4_local,
                        Network::Main,
                        false,
                        dual_stack
                    ),
                    expected
                );
            }
        }
        assert_eq!(
            announcement(None, public, local, Network::Main, false, true),
            None
        );
        assert_eq!(
            announcement(
                bound,
                None,
                Some(socket("192.168.1.2:1234")),
                Network::Main,
                false,
                true
            ),
            None
        );
        assert_eq!(
            announcement(
                bound,
                Some(socket("1.1.1.1:20000")),
                local,
                Network::Main,
                false,
                true
            ),
            Some(socket("1.1.1.1:20000"))
        );
    }

    /// An IPv6 wildcard listener with `IPV6_V6ONLY` set as given, or `None`
    /// when this host cannot bind one (no IPv6, or no dual-stack support).
    fn ipv6_wildcard(only_v6: bool) -> Option<TcpListener> {
        use socket2::{Domain, Socket, Type};
        let raw = Socket::new(Domain::IPV6, Type::STREAM, None).ok()?;
        raw.set_only_v6(only_v6).ok()?;
        raw.bind(&socket("[::]:0").into()).ok()?;
        raw.listen(1).ok()?;
        raw.set_nonblocking(true).ok()?;
        TcpListener::from_std(raw.into()).ok()
    }

    /// Whether an IPv4 loopback client reaches the listener's port.
    async fn ipv4_connects(listener: &TcpListener) -> bool {
        let port = listener.local_addr().unwrap().port();
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn ipv4_acceptance_is_read_from_the_real_socket() {
        let v4 = TcpListener::bind("0.0.0.0:0").await.unwrap();
        assert!(accepts_ipv4(&v4));
        for only_v6 in [true, false] {
            let Some(listener) = ipv6_wildcard(only_v6) else {
                eprintln!("skipping IPV6_V6ONLY={only_v6}: unsupported on this host");
                continue;
            };
            assert_eq!(accepts_ipv4(&listener), !only_v6, "IPV6_V6ONLY={only_v6}");
            assert_eq!(
                ipv4_connects(&listener).await,
                !only_v6,
                "the check disagrees with a real IPv4 connection"
            );
        }
    }

    #[test]
    fn only_outbound_peers_may_send_address_lists() {
        assert_eq!(addr_allowance(Direction::Outbound), SAMPLE_SIZE + 1);
        assert_eq!(addr_allowance(Direction::Inbound), 1);
    }

    #[test]
    fn explicit_announcements_require_a_listener_and_direct_transport() {
        let mut config = Config {
            advertise: Some(socket("127.0.0.1:19000")),
            ..Config::test()
        };
        assert!(validate(&config).is_err());
        config.listen = Some(socket("0.0.0.0:19000"));
        assert!(validate(&config).is_ok());
        config.proxy = Some(socket("127.0.0.1:9050"));
        assert!(validate(&config).is_err());
        config.proxy = None;
        config.i2p = Some(socket("127.0.0.1:7656"));
        assert!(validate(&config).is_err());
        config.i2p = None;
        config.max_inbound = 0;
        assert!(validate(&config).is_err());
    }
}
