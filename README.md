UpdateDNS
=========

Edit updatedns.ini to specify the API key for each provider hosting your DNS.
Add a FQDN entry specifying which interface to monitor and update.

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

	[yep.test.io]
	interface = eth0


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
