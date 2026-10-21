# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`updatedns` is a small CLI that manages DNS A records through Apache libcloud's DNS drivers, and in `--monitor` mode keeps records pointed at the current IPv4 address of local network interfaces. Almost all of the logic is in `updatedns/updatedns.py`. The only dependency is `apache-libcloud`.

## Commands

There are no tests, linter or CI.

```sh
pip install -e .                              # install the `updatedns` console script (entry point updatedns.updatedns:main)
python3 -m updatedns.updatedns --help         # run from the source tree without installing
updatedns -i ./updatedns.ini -v --zones       # use a local config (updatedns.ini is gitignored; start from updatedns.ini.sample)
python3 setup.py sdist                        # build dist/updatedns-<ver>.tar.gz
python3 setup.py --command-packages=stdeb.command bdist_deb   # build the Debian package into deb_dist/ (stdeb)
```

The version lives only in `updatedns/version.py`. `setup.py` `exec`s that file, so bump it there.

## Architecture

**Config loading (`UpdateDns.__init__`)**: config is read with `configparser` from these files in order, with later files overriding earlier ones: `<package dir>/updatedns.ini`, `/etc/updatedns.ini`, `~/.updatedns.ini`, then `--ini <path>`. Two settings make repeated keys work:
- `strict=False`
- the custom `MultiDict` dict type

Together they let a repeated `domain =` key accumulate into a single newline-joined value. `optionxform = str` keeps keys case-sensitive, so they pass straight through as driver kwargs.

**Section dispatch**: each section is one of two kinds, depending on its name.
- **Provider section**: the name, upper-cased, matches an attribute of `libcloud.dns.types.Provider` (for example `[route53]` becomes `Provider.ROUTE53`). Every key except `domain` goes to the libcloud driver constructor as a kwarg (`key`, `secret`, and so on). The set of supported providers depends on the installed libcloud version.
- **Host section**: any other section is treated as an FQDN and must have `interface = <ifname>`. These sections are used only by `--monitor`.

**State built at startup (`enumerate`)**: on every run, the tool lists all zones for every provider and then all **A** records in the configured zones, building these structures:
- `self.domains[domain] = [driver, zone]`: the driver is set during config parsing and the zone is appended during enumeration. A configured domain that the provider doesn't return as a zone has no zone entry, and `_find_driver` raises `ValueError` for it.
- `self.records[fqdn] = Record`: only A records are kept. The apex `@` or empty name maps to the bare domain.
- `self.zones[provider]`: every zone the provider has, used by `--zones`, which marks configured zones with `*`.

**Operations**:
- `set` creates or updates a record.
- `delete` removes records.
- `_find_driver` maps an FQDN to its zone by checking whether it is a configured domain or ends with `.` plus one, and the longest match wins.

`--list <domain...>` limits which providers and domains are loaded at all.

**Monitor mode**: this is a loop that runs every 60 seconds, or a single pass with `--once`. It reads each interface's IPv4 address with the `SIOCGIFADDR` ioctl, which works only on Linux and only for IPv4, and calls `set` for each FQDN mapped to that interface.

**Deployment files** (in `updatedns/`, shipped through `MANIFEST.in` / `include_package_data`):
- `updatedns.service`: a systemd unit that runs `updatedns --monitor`.
- `updatedns-exit-hook`: a dhclient exit hook that runs `updatedns --monitor --once` when the leased address changes.
