#!/usr/bin/env python3

import sys
import os
import argparse
import collections
import configparser
import fcntl
import json
import socket
import struct
import time

from . import version

try:
    import libcloud.dns.providers
    from libcloud.dns.types import Provider, RecordType
except ImportError:
    sys.stderr.write('Missing libcloud package\n')
    sys.exit(-1)


def main():
    argparser = argparse.ArgumentParser()

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
        help='address for new DNS entry'
        )

    argparser.add_argument('--delete', '-d',
        metavar='<name>', nargs='+',
        help='delete DNS entry'
        )

    argparser.add_argument('--monitor', '-m',
        action='store_true',
        help='monitor interfaces for changes'
        )

    argparser.add_argument('--ini', '-i',
        metavar='<path>',
        help='alternate ini file to parse'
        )

    argparser.add_argument('--verbose', '-v',
        action='store_true',
        help='enable verbose options'
        )

    argparser.add_argument('--version', '-V',
        action='version', version=f'updatedns {version.__version__}',
        help='display version and exit'
        )

    args = argparser.parse_args()

    if args.list is None and \
       not args.zones and \
       not args.monitor and \
       not args.delete and \
       not (args.name or args.addr):
            argparser.print_help()
            sys.exit(-1)

    try:
        updateDns = UpdateDns(args)
        if args.zones:
            updateDns.list_zones()
        if args.list is not None:
            updateDns.list()
        elif args.monitor:
            updateDns.monitor()
        elif args.delete:
            updateDns.delete(args.delete)
        elif args.name and args.addr:
            updateDns.create(args.name, args.addr)
        elif args.name or args.addr:
            raise ValueError('specify --name and --addr')
    except ValueError as e:
        print(f'[!] Error: {e}', file=sys.stderr)
        return -1

    return 0


class UpdateDns:
    def __init__(self, args):
        self.interfaces = collections.defaultdict(list)
        self.zones      = collections.defaultdict(list)
        self.drivers    = {}
        self.domains    = {}
        self.records    = {}
        self.verbose    = args.verbose

        # get a list of providers that this version of libcloud supports
        libcloud_providers = []
        for provider in dir(Provider):
            if provider.startswith('__'):
                continue
            libcloud_providers.append(provider)

        ini = configparser.ConfigParser(dict_type=MultiDict, strict=False)
        ini.optionxform = str

        ini_paths = [
            os.path.join(os.path.dirname(__file__), 'updatedns.ini'),
            '/etc/updatedns.ini',
            os.path.expanduser('~/.updatedns.ini'),
            ]

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
                host = dict(ini.items(section))
                if 'interface' not in host:
                    self._log('[-] Missing interface from host {section}', file=sys.stderr)
                    continue
                self.interfaces[host['interface']].append(hostname)

        self.enumerate()

    def _log(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def enumerate(self):
        for provider,driver in self.drivers.items():
            try:
                zones = driver.list_zones()
            except Exception as e:
                self._log(f'[-] Warning: {provider}: {e}', file=sys.stderr)
                continue

            for zone in zones:
                zone_domain = zone.domain
                if zone_domain.endswith('.'):
                    zone_domain = zone_domain[:-1]

                self.zones[provider].append(zone_domain)

                if zone_domain not in self.domains:
                    self._log(f'Skipping {zone_domain}')
                    continue

                self.domains[zone_domain].append(zone)

                for record in driver.list_records(zone):
                    if record.type != 'A':
                        continue
                    domain_name = zone.domain
                    if domain_name.endswith('.'):
                        domain_name = domain_name[:-1]

                    fqdn = domain_name
                    if record.name and record.name != '@':
                        fqdn = record.name + '.' + fqdn

                    self.records[fqdn] = record

    def list_zones(self):
        for provider,zones in self.zones.items():
            print(provider)
            for zone in zones:
                prefix = '*' if zone in self.domains else ' '
                print(f'{prefix} {zone}')
            print()

    def list(self):
        for fqdn,record in self.records.items():
            print(f'{record.data:16} {fqdn}')

    def _find_driver(self, fqdn):
        for zone_domain in self.domains:
            if not fqdn.endswith(zone_domain):
                continue
            driver,zone = self.domains[zone_domain]
            name = fqdn[:-(len(zone_domain)+1)]
            return driver,zone,name
        raise ValueError('Unknown domain:', fqdn)

    def create(self, fqdn, addr):
        driver,zone,name = self._find_driver(fqdn)

        if fqdn in self.records:
            record = self.records[fqdn]
            if addr != record.data:
                self.records[fqdn] = driver.update_record(record, data=addr)
                self._log(f'Updated: {fqdn} = {addr}')
                return True
            else:
                self._log(f'No change: {fqdn} = {addr}')
        else:
            try:
                self.records[fqdn] = driver.create_record(name, zone, RecordType.A, addr)
                self._log(f'Created: {fqdn} = {addr}')
                return True
            except Exception as e:
                print(f'[!] Error: {e}', file=sys.stderr)

    def delete(self, fqdns):
        for fqdn in fqdns:
            if fqdn not in self.records:
                self._log(f'Unknown host: {fqdn}')
                continue

            driver,zone,name = self._find_driver(fqdn)

            driver.delete_record(self.records[fqdn])
            del self.records[fqdn]
            self._log(f'Deleted: {fqdn}')

    def monitor(self):
        def get_local_address(ifname):
            SIOCGIFADDR = 0x8915
            skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifname = ifname[:15].encode('ascii')
            ifname = struct.pack('256s', ifname)
            data = fcntl.ioctl(skt.fileno(), SIOCGIFADDR, ifname)
            return socket.inet_ntoa(data[20:24])

        while True:
            for interface,fqdns in self.interfaces.items():
                try:
                    local_address = get_local_address(interface)
                except Exception as e:
                    self._log(f'Could not get address for interface {interface}: {e}')
                    continue
                for fqdn in fqdns:
                    modified = self.create(fqdn,local_address)
                    if modified:
                        self._log(f'Updated: {fqdn} = {local_address}')
            time.sleep(60.0)


class MultiDict(dict):
    def __setitem__(self, key, value):
        if key in self and isinstance(value, list):
            self[key].extend(value)
        else:
            super(MultiDict, self).__setitem__(key, value)


if '__main__' == __name__:
    sys.exit(main())
