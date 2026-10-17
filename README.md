# dbo-vpn-gateway

An OpenVPN 2.7 remote-access gateway for Rocky Linux / RHEL 9, packaged as one RPM.

- **VPN users** connect with a certificate plus their password and a 6-digit authenticator (TOTP) code. They never log in to the panel; they open a one-time setup link, choose a password, add the account to an authenticator app and download their `.ovpn` profile.
- **Customer admins** manage VPN users in a small web panel (Turkish and English): create, disable, enable, extend, reset, delete, disconnect, and read the audit log.
- **The operator** (root over SSH) sets the user limit and access profiles, creates panel admins and runs setup, all from the `dbo-vpn-gateway` command. None of this is reachable from the web.

Every customer-specific value is in one file, `/etc/dbo-vpn-gateway/gateway.conf`, so the same RPM serves any number of customers.

## How it fits together

| Piece | Runs as | What it does |
|---|---|---|
| `openvpn-server@<instance>` | openvpn | The VPN. Asks the management daemon to approve every connection. |
| `dbo-vpn-gateway-mgmt` | dbovpn | Connects to OpenVPN's management socket. Checks certificate name, account state, password and TOTP; gives each user a fixed VPN address and the routes of their access profile. If it is down, nobody new can connect. |
| `dbo-vpn-gateway-web` | dbovpn | The panel and the public setup page (gunicorn on 127.0.0.1). |
| nginx | nginx | HTTPS in front of the panel. `/enroll/` is public (rate limited); everything else only from `admin_allow` networks. |
| `privhelper` | root via sudo | The only root path from the panel: issue or revoke a certificate, build a `.ovpn`, add or remove a VPN address in a profile ipset. Every argument is validated. |
| `dbo-vpn-gateway-expiry.timer` | dbovpn | Hourly: expires accounts and disconnects them, mails admins 7 days before and on the last valid day, purges used setup links. |
| `dbo-vpn-gateway-crl-renew.timer` | root | Monthly CRL renewal; warns 60 days before the server certificate expires. |
| `dbo-vpn-gateway-autoupdate.timer` | root | Nightly OpenVPN-only update; restarts OpenVPN only if the package or its libraries changed. |

Network flow: VPN clients connect to this server on the OpenVPN port (default UDP 1194). Their traffic leaves through firewalld policy `dbovpn-forward` with masquerade, and only to the destinations of their access profile. The firewalld zone `openvpn` (target DROP) holds the tun interface, so VPN clients cannot reach the gateway itself. Admins reach the panel on TCP 443 from the `admin_allow` networks; VPN users reach `/enroll/` on TCP 443 from anywhere.

## Install

On a fresh Rocky Linux 9 or RHEL 9 server, as root.

1. Enable EPEL and the OpenVPN 2.7 Copr repository (the RPM needs `openvpn >= 2.7` from there and `easy-rsa`, `python3-gunicorn`, `python3-argon2-cffi`, `python3-qrcode-core`, `python3-flask-wtf` from EPEL):

   ```
   dnf install epel-release            # on RHEL 9: see https://docs.fedoraproject.org/en-US/epel/
   dnf config-manager --set-enabled crb
   dnf copr enable @OpenVPN/openvpn-release-2.7   # https://copr.fedorainfracloud.org/coprs/g/OpenVPN/openvpn-release-2.7/
   ```

2. Install the RPM from the GitHub release:

   ```
   dnf -y install --setopt=install_weak_deps=False https://github.com/Sh3rm/dbo-vpn-gateway/releases/download/v1.0.0/dbo-vpn-gateway-1.0.0-1.el9.noarch.rpm
   ```

   `install_weak_deps=False` matters: otherwise the Copr openvpn package pulls in its data-channel-offload kernel module through DKMS (dkms, gcc, kernel-devel, llvm: about 50 packages), which the gateway does not use.

3. Create the configuration from the example and edit it:

   ```
   cp /usr/share/doc/dbo-vpn-gateway/gateway.conf.example /etc/dbo-vpn-gateway/gateway.conf
   chown root:dbovpn /etc/dbo-vpn-gateway/gateway.conf
   chmod 0640 /etc/dbo-vpn-gateway/gateway.conf
   vi /etc/dbo-vpn-gateway/gateway.conf
   ```

4. Put the TLS certificate and key for `public_hostname` where `tls_cert` and `tls_key` point.

5. Run setup, then create the first panel admin:

   ```
   dbo-vpn-gateway setup --apply
   dbo-vpn-gateway admin add ayse.yilmaz --name "Ayse Yilmaz" --email ayse@example.com --lang tr
   ```

   `admin add` prints a one-time setup link and mails it. The admin opens it from an `admin_allow` network, sets a password and adds the authenticator, then signs in at `https://<public_hostname>/`.

6. Check everything:

   ```
   dbo-vpn-gateway doctor
   ```

## gateway.conf

The example file (`/usr/share/doc/dbo-vpn-gateway/gateway.conf.example`) documents every key. The ones you always set:

- `[gateway] customer_name`, `public_hostname`: shown to users, used in profiles and links.
- `[openvpn] instance`, `port`, `proto`, `subnet`: the OpenVPN server. Each user gets a fixed address from `subnet`.
- `[users] max_users`: the user limit. Every VPN user that is not deleted counts, including disabled and expired ones. Admins do not count.
- `[panel] admin_allow`, `tls_cert`, `tls_key`: who may open the panel, and the HTTPS certificate.
- `[mail] relay_host`, `sender`: a relay on port 25 that accepts mail from this server without a password. STARTTLS is used when the relay offers it.
- `[profile NAME]` sections: what users may reach. Exactly one has `default = yes`; new users get it.

After changing the file, run `dbo-vpn-gateway setup`.

## setup

`dbo-vpn-gateway setup` is safe to run again at any time. It:

- creates the PKI with Easy-RSA if there is none (CA, server certificate, tls-crypt key, CRL), or keeps an existing one;
- writes `/etc/openvpn/server/<instance>.conf` (a timestamped backup of the old file is kept), the nginx site, sysctl, audit rules and the dnf-automatic file;
- configures firewalld permanently: zone, policy, one ipset per profile, the profile rules, the OpenVPN and HTTPS ports;
- starts firewalld if it is installed but stopped; before that it reads the SSH port(s) from `sshd -T` and allows them in the public and default zone (with `firewall-offline-cmd`), so you are not locked out. It prints what it allowed and never removes anything you configured;
- creates or migrates the database and imports every valid client certificate that is not yet a user (adoption, see below);
- enables and starts the gateway services and timers.

A firewalld reload and an OpenVPN restart disconnect every VPN user for a few seconds, so plain `setup` never does them. It prints `PENDING` when they are needed; run `dbo-vpn-gateway setup --apply` in a maintenance window.

### Adopting an existing OpenVPN server

Point `pki_dir`, `server_cert_name`, `tls_crypt_key`, `crl_file` and `instance` at the existing files. Setup keeps the PKI and every certificate, imports each valid client certificate as a user (default profile, default expiry, a fixed address; adoption ignores the user limit), disables the old CRL and update timers it replaces, and renames old audit and sysctl drop-ins with the suffix `.retired-by-dbo-vpn-gateway`.

Adopted users have no password or authenticator yet. Give each one an e-mail address and a setup link before the switch:

```
dbo-vpn-gateway user update ali.veli --name "Ali Veli" --email ali@example.com
dbo-vpn-gateway user link ali.veli
```

Run `setup` without `--apply` first, let users enrol and import their new profile, then run `setup --apply` in a maintenance window. From then on a password and code are required.

## Daily commands

```
dbo-vpn-gateway status                       # services, connected users, usage
dbo-vpn-gateway limit                        # n / max_users, by status
dbo-vpn-gateway user list
dbo-vpn-gateway user show ali.veli
dbo-vpn-gateway admin list
dbo-vpn-gateway admin reset ayse.yilmaz      # new password + authenticator via a new link
dbo-vpn-gateway admin disable ayse.yilmaz    # also signs the admin out everywhere
dbo-vpn-gateway admin enable ayse.yilmaz     # also clears a login lockout
dbo-vpn-gateway profile list
dbo-vpn-gateway profile add db --dest 203.0.113.30/32:1521/tcp --description "Database"
dbo-vpn-gateway profile assign ali.veli db   # disconnects the user so new routes apply
dbo-vpn-gateway doctor
```

The audit table records every change with time, actor, action, target, detail and source IP: panel and CLI actions, admin and VPN logins and failures, disconnects and the expiry job.

## Rules the gateway enforces

- **User limit:** creating a user beyond `max_users` is refused. Only deleting a user frees a slot.
- **Expiry:** every VPN user has a last valid day, 90 days ahead by default and at most 365 days from today. From the next day the account cannot connect, is disconnected, and still counts against the limit until an admin extends or deletes it.
- **Disable, enable, extend** never touch the certificate. **Delete** revokes the certificate, regenerates the CRL, disconnects the user and removes it (the audit log keeps the history). **Reset** clears password and authenticator and sends a new setup link; the certificate stays.
- **Login:** certificate name must equal the user name; password and authenticator code are checked on connect (static challenge, SCRV1). A code works once. After the first login, OpenVPN's session token (`auth-gen-token ... external-auth`) covers the hourly key renegotiation, and the gateway still re-checks that the account is enabled and not expired each time. The token lifetime (`auth_token_lifetime_hours`, default 12) sets how often users type a new code. A reset, disable, expiry or delete ends every token issued before it. After 5 wrong passwords or codes (`lockout_attempts`) a VPN account is locked for 15 minutes (`lockout_minutes`); enabling the user in the panel clears the lock.
- **OpenVPN restart:** after OpenVPN restarts (update, `setup --apply`, reboot) every user logs in again with password and code. This is by design: the session-token key lives only in OpenVPN's memory (no `auth-gen-token-secret` file), so no long-lived secret sits on disk.
- **Certificates:** new client certificates are valid `client_cert_days` (default `max_expiry_days` + 90 = 455 days). When a user downloads a profile after a setup link, the gateway first issues a fresh key and certificate if the current one would end before the last valid day + 30 days, if the key is passphrase-protected, or if the user was adopted from a legacy setup; the old serial is revoked only after the new pair exists (Easy-RSA `expire`, `build-client-full`, `revoke-expired`, `gen-crl`). A profile never contains a passphrase-protected key. If an account is later extended past its certificate, the panel shows it, `doctor` fails, and the hourly job mails the admins once; resetting the user fixes it.
- **Panel:** user name + password + code; the account locks for `lockout_minutes` after `lockout_attempts` failures; sessions end after 30 minutes without activity; every form has a CSRF token.

## Development

The code is Python 3.9 (the system `python3` on EL9) and uses only the standard library plus the RPMs above. Core logic imports without Flask or argon2, so the tests run anywhere:

```
make test       # python3 -m unittest discover -s tests -t .
```

The web tests are skipped when Flask is not installed. `make rpm` builds the RPM on an EL9 host with `rpm-build`, `python3-devel` and `systemd-rpm-macros`.

## License

Apache License 2.0, see `LICENSE` and `NOTICE`.
