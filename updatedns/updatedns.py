#!/usr/bin/env python3

import sys
import os
import argparse
import collections
import configparser
import fcntl
import ipaddress
import logging
import socket
import struct
import time

from . import version

try:
    import libcloud.dns.providers
    from libcloud.dns.types import Provider, RecordType
except ImportError:
    sys.exit('Missing libcloud package')


log = logging.getLogger('updatedns')

INI_PATHS = [
    os.path.join(os.path.dirname(__file__), 'updatedns.ini'),
    '/etc/updatedns.ini',
    os.path.expanduser('~/.updatedns.ini'),
    ]


def main(argv=None):
    argparser = argparse.ArgumentParser(
        prog='updatedns',
        description='Manage DNS A and AAAA records with any DNS provider that '
                    'Apache libcloud supports, and keep them pointed at the '
                    'addresses of local network interfaces.',
        )

    argparser.add_argument('--zones', '-z',
        action='store_true',
        help='list all zones available for configured providers'
        )

    argparser.add_argument('--list', '-l',
        metavar='<domain>', nargs='*',
        help='list all records in configured zones'
        )

    argparser.add_argument('--name', '-n',
        metavar='<name>',
        help='create or update new DNS entry'
        )

    argparser.add_argument('--addr', '-a',
        metavar='<ip>',
        help='IPv4 or IPv6 address for DNS entry'
        )

    argparser.add_argument('--delete', '-d',
        metavar='<name>', nargs='+',
        help='delete DNS entry'
        )

    argparser.add_argument('--monitor', '-m',
        action='store_true',
        help='monitor interfaces for changes'
        )

    argparser.add_argument('--once', '-1',
        action='store_true',
        help='with --monitor, check interfaces once and exit'
        )

    argparser.add_argument('--ini', '-i',
        metavar='<path>',
        help='alternate ini file to parse'
        )

    argparser.add_argument('--verbose', '-v',
        action='count', default=0,
        help='log changes (-v) or everything (-vv)'
        )

    argparser.add_argument('--version', '-V',
        action='version', version=f'updatedns {version.__version__}',
        help='display version and exit'
        )

    args = argparser.parse_args(argv)

    if args.list is None and \
       not args.zones and \
       not args.monitor and \
       not args.delete and \
       not (args.name or args.addr):
            argparser.print_help()
            return 1

    # only raise our own logger's level so -vv doesn't turn on libcloud/urllib3 debugging
    logging.basicConfig(format='%(levelname)s: %(message)s')
    log.setLevel([logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)])

    try:
        updateDns = UpdateDns(args)
        if args.zones:
            updateDns.list_zones()
        if args.list is not None:
            updateDns.list()
        elif args.monitor:
            updateDns.monitor(args.once)
        elif args.delete:
            updateDns.delete(args.delete)
        elif args.name and args.addr:
            updateDns.set(args.name, args.addr)
        elif args.name or args.addr:
            raise ValueError('specify --name and --addr')
    except ValueError as e:
        log.error(e)
        return 1

    return 1 if updateDns.errors else 0


class UpdateDns:
    def __init__(self, args):
        self.interfaces = collections.defaultdict(list)
        self.zones      = collections.defaultdict(list)
        self.drivers    = {}
        self.domains    = {}
        self.records    = {}
        self.errors     = 0

        # get a list of providers that this version of libcloud supports
        libcloud_providers = []
        for provider in dir(Provider):
            if provider.startswith('__'):
                continue
            libcloud_providers.append(provider)

        ini = configparser.ConfigParser(dict_type=MultiDict, strict=False)
        ini.optionxform = str

        ini_paths = list(INI_PATHS)
        if args.ini:
            ini_paths.append(args.ini)

        try:
            ok = ini.read(ini_paths)
        except configparser.ParsingError as e:
            raise ValueError(f'Parsing error: {e}') from None
        if not ok:
            raise ValueError(f'Could not open any ini file') from None

        for section in ini.sections():
            provider = section.strip().upper()
            hostname = section.strip()

            # check to see if section name is a DNS provider
            if provider in libcloud_providers:
                credentials = dict(ini.items(section))

                domains = credentials.pop('domain', '')
                domains = domains.split('\n')

                if args.list:
                    in_zone = False
                    for l in args.list:
                        if l in domains:
                            in_zone = True
                            break
                    if not in_zone:
                        continue

                Driver = libcloud.dns.providers.get_driver(getattr(Provider, provider))
                driver = Driver(**credentials)
                self.drivers[provider] = driver

                for domain in domains:
                    if args.list and domain not in args.list:
                        continue
                    self.domains[domain] = [driver]
            else:
                host = ini[section]
                if 'interface' not in host:
                    log.warning(f'Missing interface from host {section}')
                    continue

                try:
                    record_types = []
                    if host.getboolean('ipv4', fallback=True):
                        record_types.append(RecordType.A)
                    if host.getboolean('ipv6', fallback=False):
                        record_types.append(RecordType.AAAA)
                except ValueError as e:
                    raise ValueError(f'{section}: {e}') from None
                if not record_types:
                    log.warning(f'Both ipv4 and ipv6 are off for host {section}')
                    continue

                self.interfaces[host['interface']].append((hostname, record_types))

        self.enumerate()

    def _error(self, message):
        log.error(message)
        self.errors += 1

    def enumerate(self):
        for provider,driver in self.drivers.items():
            try:
                zones = driver.list_zones()
            except Exception as e:
                self._error(f'{provider}: {e}')
                continue

            for zone in zones:
                zone_domain = zone.domain
                if zone_domain.endswith('.'):
                    zone_domain = zone_domain[:-1]

                self.zones[provider].append(zone_domain)

                if zone_domain not in self.domains:
                    log.debug(f'Skipping {zone_domain}')
                    continue

                self.domains[zone_domain].append(zone)

                try:
                    records = driver.list_records(zone)
                except Exception as e:
                    self._error(f'{provider}: {zone_domain}: {e}')
                    continue

                for record in records:
                    if record.type not in ADDRESS_LOOKUP:
                        continue

                    fqdn = zone_domain
                    if record.name and record.name != '@':
                        fqdn = record.name + '.' + fqdn

                    self.records[(fqdn, record.type)] = record

        for domain,entry in self.domains.items():
            if len(entry) < 2:
                log.warning(f'Zone not found at provider: {domain}')

    def list_zones(self):
        for provider,zones in self.zones.items():
            print(provider)
            for zone in zones:
                prefix = '*' if zone in self.domains else ' '
                print(f'{prefix} {zone}')
            print()

    def list(self):
        width = max((len(record.data) for record in self.records.values()), default=0)
        for (fqdn,record_type),record in self.records.items():
            print(f'{record.data:{width}} {record_type:4} {fqdn}')

    def _find_driver(self, fqdn):
        # longest match first so a configured sub-zone wins over its parent
        for zone_domain in sorted(self.domains, key=len, reverse=True):
            if fqdn != zone_domain and not fqdn.endswith('.' + zone_domain):
                continue
            if len(self.domains[zone_domain]) < 2:
                raise ValueError(f'Zone not found at provider: {zone_domain}')
            driver,zone = self.domains[zone_domain]
            name = fqdn[:-(len(zone_domain)+1)]
            return driver,zone,name
        raise ValueError(f'Unknown domain: {fqdn}')

    def set(self, fqdn, addr):
        try:
            addr = ipaddress.ip_address(addr)
        except ValueError:
            raise ValueError(f'Invalid address: {addr}') from None
        record_type = RecordType.A if addr.version == 4 else RecordType.AAAA

        driver,zone,name = self._find_driver(fqdn)

        key = (fqdn, record_type)
        if key in self.records:
            record = self.records[key]
            if not same_address(addr, record.data):
                try:
                    self.records[key] = driver.update_record(record, data=str(addr))
                    log.info(f'Updated {fqdn} {record_type} {addr}')
                except Exception as e:
                    self._error(f'{fqdn}: {e}')
            else:
                log.debug(f'No change {fqdn} {record_type} {addr}')
        else:
            try:
                self.records[key] = driver.create_record(name, zone, record_type, str(addr))
                log.info(f'Created {fqdn} {record_type} {addr}')
            except Exception as e:
                self._error(f'{fqdn}: {e}')

    def delete(self, fqdns):
        for fqdn in fqdns:
            keys = [key for key in self.records if key[0] == fqdn]
            if not keys:
                self._error(f'Unknown host: {fqdn}')
                continue

            driver,zone,name = self._find_driver(fqdn)

            for key in keys:
                try:
                    driver.delete_record(self.records[key])
                except Exception as e:
                    self._error(f'{fqdn}: {e}')
                    continue
                del self.records[key]
                log.info(f'Deleted {fqdn} {key[1]}')

    def monitor(self, once=False):
        while True:
            for interface,hosts in self.interfaces.items():
                addresses = {}
                for fqdn,record_types in hosts:
                    for record_type in record_types:
                        if record_type not in addresses:
                            try:
                                addresses[record_type] = ADDRESS_LOOKUP[record_type](interface)
                            except (OSError, LookupError) as e:
                                self._error(f'Could not get {record_type} address for interface {interface}: {e}')
                                addresses[record_type] = None
                        if addresses[record_type] is None:
                            continue
                        try:
                            self.set(fqdn, addresses[record_type])
                        except ValueError as e:
                            self._error(e)
            if once:
                break
            time.sleep(60.0)


def same_address(addr, data):
    # providers may hand back IPv6 addresses in a different textual form
    try:
        return addr == ipaddress.ip_address(data)
    except ValueError:
        return False


def ipv4_address(ifname):
    SIOCGIFADDR = 0x8915
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as skt:
        ifname = ifname[:15].encode('ascii')
        ifname = struct.pack('256s', ifname)
        data = fcntl.ioctl(skt.fileno(), SIOCGIFADDR, ifname)
    return socket.inet_ntoa(data[20:24])


# address flags from linux/if_addr.h that make an address a poor DNS target
IFA_F_TEMPORARY  = 0x01
IFA_F_DADFAILED  = 0x08
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE  = 0x40

def ipv6_address(ifname, path='/proc/net/if_inet6'):
    # each line is: address ifindex prefixlen scope flags ifname, all hex but ifname
    with open(path) as fp:
        for line in fp:
            fields = line.split()
            if len(fields) != 6 or fields[5] != ifname:
                continue
            if int(fields[4], 16) & (IFA_F_TEMPORARY | IFA_F_DADFAILED | IFA_F_DEPRECATED | IFA_F_TENTATIVE):
                continue
            addr = ipaddress.IPv6Address(bytes.fromhex(fields[0]))
            if addr.is_global:
                return str(addr)
    raise LookupError('no stable global IPv6 address')


ADDRESS_LOOKUP = {
    RecordType.A    : ipv4_address,
    RecordType.AAAA : ipv6_address,
    }


class MultiDict(dict):
    def __setitem__(self, key, value):
        if key in self and isinstance(value, list):
            self[key].extend(value)
        else:
            super(MultiDict, self).__setitem__(key, value)


if '__main__' == __name__:
    sys.exit(main())
