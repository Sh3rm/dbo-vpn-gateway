# dbo-vpn-gateway developer helpers. Nothing here installs anything.
VERSION := $(shell sed -n 's/^Version: *//p' dbo-vpn-gateway.spec)

.PHONY: test check tarball rpm

test:
	python3 -m unittest discover -s tests -t .

# Python 3.9 grammar + compile check of every file (also part of test).
check:
	python3 -m unittest tests.test_syntax

tarball:
	mkdir -p dist
	git archive --format=tar.gz --prefix=dbo-vpn-gateway-$(VERSION)/ -o dist/dbo-vpn-gateway-$(VERSION).tar.gz HEAD

# On a Rocky/RHEL 9 build host with rpm-build, python3-devel and systemd-rpm-macros.
rpm: tarball
	rpmbuild -ta dist/dbo-vpn-gateway-$(VERSION).tar.gz
