"""dbo-vpn-gateway: OpenVPN 2.7 remote-access gateway with a self-service web panel."""

__version__ = "1.0.1"

CONFIG_PATH = "/etc/dbo-vpn-gateway/gateway.conf"
SERVICE_USER = "dbovpn"
PRIVHELPER_PATH = "/usr/libexec/dbo-vpn-gateway/privhelper"
CTL_SOCKET = "/run/dbo-vpn-gateway/ctl.sock"
