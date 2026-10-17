Name:           dbo-vpn-gateway
Version:        1.0.2
Release:        1%{?dist}
Summary:        OpenVPN 2.7 remote-access gateway with a self-service web panel
License:        Apache-2.0
URL:            https://github.com/Sh3rm/dbo-vpn-gateway
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  systemd-rpm-macros

# Runtime: BaseOS/AppStream/EPEL 9 and the OpenVPN Copr; nothing from pip.
# TOTP is implemented with the standard library, so python3-pyotp is not needed.
Requires:       python3
Requires:       python3-flask
Requires:       python3-flask-wtf
Requires:       python3-gunicorn
Requires:       python3-qrcode-core
Requires:       python3-argon2-cffi
Requires:       sqlite
Requires:       nginx
Requires:       openvpn >= 2.7
Requires:       easy-rsa >= 3.2
Requires:       firewalld
Requires:       sudo
Requires:       openssl
Requires:       audit
Requires:       dnf-automatic
Requires:       dnf-plugins-core
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
Requires:       openssh-server
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
OpenVPN 2.7 remote-access gateway for Rocky Linux / RHEL 9. VPN users log in
with certificate + password + TOTP; customer admins manage users in a web
panel (TR/EN); DBO manages caps, access profiles and admins from a root CLI.
All customer-specific values come from /etc/dbo-vpn-gateway/gateway.conf.

%prep
%autosetup -n %{name}-%{version}

%build
# Pure Python, nothing to build.

%install
install -d %{buildroot}%{python3_sitelib}
cp -a dbovpn %{buildroot}%{python3_sitelib}/
find %{buildroot}%{python3_sitelib}/dbovpn -name __pycache__ -prune -exec rm -rf {} +

install -D -m 0755 bin/dbo-vpn-gateway %{buildroot}%{_sbindir}/dbo-vpn-gateway
install -D -m 0755 bin/privhelper %{buildroot}%{_libexecdir}/%{name}/privhelper

install -d %{buildroot}%{_unitdir}
install -m 0644 systemd/*.service systemd/*.timer %{buildroot}%{_unitdir}/

install -D -m 0440 conf/sudoers %{buildroot}%{_sysconfdir}/sudoers.d/%{name}
install -d -m 0750 %{buildroot}%{_sysconfdir}/%{name}
install -d -m 0700 %{buildroot}%{_sharedstatedir}/%{name}

# Files written by 'dbo-vpn-gateway setup' (owned here so rpm -qf finds them).
install -d %{buildroot}%{_sysconfdir}/nginx/conf.d %{buildroot}%{_sysconfdir}/sysctl.d \
           %{buildroot}%{_sysconfdir}/audit/rules.d %{buildroot}%{_sysconfdir}/dnf
touch %{buildroot}%{_sysconfdir}/nginx/conf.d/%{name}.conf \
      %{buildroot}%{_sysconfdir}/sysctl.d/90-%{name}.conf \
      %{buildroot}%{_sysconfdir}/audit/rules.d/51-%{name}.rules \
      %{buildroot}%{_sysconfdir}/dnf/automatic-%{name}.conf \
      %{buildroot}%{_sysconfdir}/%{name}/web.env

%check
%{python3} -m unittest discover -s tests -t .

%pre
getent group dbovpn >/dev/null || groupadd -r dbovpn
getent passwd dbovpn >/dev/null || \
    useradd -r -g dbovpn -d %{_sharedstatedir}/%{name} -s /sbin/nologin \
            -c "dbo-vpn-gateway service" dbovpn
exit 0

%post
%systemd_post dbo-vpn-gateway-mgmt.service dbo-vpn-gateway-web.service dbo-vpn-gateway-expiry.timer dbo-vpn-gateway-crl-renew.timer dbo-vpn-gateway-autoupdate.timer

%preun
%systemd_preun dbo-vpn-gateway-mgmt.service dbo-vpn-gateway-web.service dbo-vpn-gateway-expiry.timer dbo-vpn-gateway-crl-renew.timer dbo-vpn-gateway-autoupdate.timer

%postun
%systemd_postun_with_restart dbo-vpn-gateway-mgmt.service dbo-vpn-gateway-web.service
%systemd_postun dbo-vpn-gateway-expiry.timer dbo-vpn-gateway-crl-renew.timer dbo-vpn-gateway-autoupdate.timer

%files
%license LICENSE NOTICE
%doc README.md conf/gateway.conf.example
%{python3_sitelib}/dbovpn/
%{_sbindir}/dbo-vpn-gateway
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/privhelper
%{_unitdir}/dbo-vpn-gateway-*.service
%{_unitdir}/dbo-vpn-gateway-*.timer
%config(noreplace) %attr(0440,root,root) %{_sysconfdir}/sudoers.d/%{name}
%dir %attr(0750,root,dbovpn) %{_sysconfdir}/%{name}
%dir %attr(0700,dbovpn,dbovpn) %{_sharedstatedir}/%{name}
%ghost %config(noreplace) %{_sysconfdir}/nginx/conf.d/%{name}.conf
%ghost %config(noreplace) %{_sysconfdir}/sysctl.d/90-%{name}.conf
%ghost %config(noreplace) %{_sysconfdir}/audit/rules.d/51-%{name}.rules
%ghost %config(noreplace) %{_sysconfdir}/dnf/automatic-%{name}.conf
%ghost %config(noreplace) %{_sysconfdir}/%{name}/web.env

%changelog
* Sat Oct 17 2026 Sh3rm - 1.0.2-1
- Favicon: the full DBO logo instead of a single letter

* Sat Oct 17 2026 Sh3rm - 1.0.1-1
- Favicon: draw the logo "b" so it reads correctly at tab size

* Sat Oct 17 2026 Sh3rm - 1.0.0-1
- First release
