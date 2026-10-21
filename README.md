UpdateDNS
=========

Command-line tool for managing DNS A and AAAA records with any DNS provider
that Apache libcloud supports. It can also keep records pointed at the
current addresses of local network interfaces, which makes it work as a
dynamic DNS client. Monitoring interfaces works on Linux only.

	pip install updatedns


Configuration
-------------

Settings are read from these files, in order, with later files overriding
earlier ones:

* `updatedns.ini` in the package directory
* `/etc/updatedns.ini`
* `~/.updatedns.ini`
* the file given with `--ini <path>`

Add a section for each provider hosting your DNS, named after the libcloud
provider, with its API credentials and the domains it hosts. Add a section
for each FQDN to keep updated, with the interface whose address it should
follow. Hosts get an A record by default. Set `ipv6 = yes` to also keep an
AAAA record, and `ipv4 = no` to skip the A record.

	[digital_ocean]
	key       = <api key>
	domain    = domain.tld

	[route53]
	key       = <api key>
	secret    = <secret>
	domain    = example.com
	domain    = test.io

	[sub.domain.tld]
	interface = wan0

	[yep.example.com]
	interface = eth0
	ipv6      = yes

	[yep.test.io]
	interface = eth0

For the AAAA record, the interface's first global IPv6 address is used.
Temporary (privacy) addresses, deprecated addresses and ULA addresses are
skipped.


Usage
-----

	updatedns --zones                                 # zones at each provider, configured ones marked *
	updatedns --list                                  # A and AAAA records in the configured zones
	updatedns --name host.example.com --addr 1.2.3.4  # create or update a record
	updatedns --name host.example.com --addr 2001:db8::1
	updatedns --delete host.example.com               # delete its A and AAAA records
	updatedns --monitor                               # update interface hosts every 60 seconds
	updatedns --monitor --once                        # update interface hosts once and exit

Add `-v` to log changes, or `-vv` to log everything. Errors and warnings
always go to stderr. The exit status is 1 if anything failed.


Running it automatically
------------------------

The Debian package (`python3-updatedns`) installs the systemd unit and all
the hooks below for you. The service is installed disabled: create
`/etc/updatedns.ini` and then run `systemctl enable --now updatedns`. The
hooks do nothing until `/etc/updatedns.ini` or `/root/.updatedns.ini`
exists.

With a pip install, copy the files into place yourself. Find them with
`python3 -c 'import updatedns, os; print(os.path.dirname(updatedns.__file__))'`.

* `updatedns.service` runs `updatedns --monitor --verbose` and restarts it
  if it fails. Copy it to `/etc/systemd/system/`, then run
  `systemctl enable --now updatedns`.
* `updatedns-nm-dispatcher` is for NetworkManager. Install it as
  `/etc/NetworkManager/dispatcher.d/90-updatedns`, owned by root with mode 0755.
* `updatedns-networkd-dispatcher` is for systemd-networkd with
  networkd-dispatcher. Install it as
  `/etc/networkd-dispatcher/routable.d/50-updatedns`, owned by root with mode 0755.
* `updatedns-exit-hook` is for dhclient. Install it as
  `/etc/dhcp/dhclient-exit-hooks.d/updatedns`.

Each hook runs `updatedns --monitor --once` when the network comes up or a
DHCP lease changes, and logs to syslog under the tag `updatedns`. The
service also catches address changes the hooks don't see, such as new
SLAAC IPv6 addresses.


Providers as of libcloud-3.7.0
------------------------------
* auroradns
* buddyns
* cloudflare
* digital_ocean
* dnsimple
* durabledns
* gandi
* gandi_live
* godaddy
* google
* hostvirtual
* linode
* liquidweb
* luadns
* nfsn
* nsone
* onapp
* pointdns
* powerdns
* rackspace
* rcodezero
* route53
* softlayer
* vultr
* worldwidedns
* zerigo
* zonomi
