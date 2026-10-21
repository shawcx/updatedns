# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`updatedns` is a small CLI that manages DNS A and AAAA records through Apache libcloud's DNS drivers. In `--monitor` mode it keeps records pointed at the current addresses of local network interfaces. Almost all of the logic is in `updatedns/updatedns.py`. The only runtime dependency is `apache-libcloud`.

## Commands

```sh
python3 -m pytest                             # run the tests (tests/test_updatedns.py)
python3 -m pytest -k find_driver              # run a subset by name
pip install -e .                              # install the `updatedns` console script (entry point updatedns.updatedns:main)
python3 -m updatedns.updatedns --help         # run from the source tree without installing
updatedns -i ./updatedns.ini -v --zones       # use a local config (updatedns.ini is gitignored; start from updatedns.ini.sample)
python3 -m build --no-isolation               # build the sdist and wheel into dist/
python3 setup.py --command-packages=stdeb.command bdist_deb   # build the Debian package into deb_dist/ (stdeb)
```

There's no linter or CI.

## Packaging

- Metadata lives in `pyproject.toml`.
- The version lives only in `updatedns/version.py`, which `pyproject.toml` reads as a dynamic `attr`.
- `setup.py` is a shim kept for stdeb. stdeb can't find the Debian Maintainer or Homepage in pyproject metadata (it checks for `'UNKNOWN'`, but setuptools returns `None`), so the shim passes `url` and the `sdist_dsc` maintainer option.
- Don't add a `stdeb.cfg`: stdeb 0.10 on Python 3.12 crashes reading it, because it calls the removed `ConfigParser.readfp`.
- Package data is listed explicitly in `MANIFEST.in` and `[tool.setuptools.package-data]`, so a stray `updatedns/updatedns.ini` holding real credentials never ships.

## Tests

The tests replace `libcloud.dns.providers.get_driver` with a `FakeDriver`, and override `updatedns.INI_PATHS` so the real `/etc` and `~` config files are never read. They stub `updatedns.ADDRESS_LOOKUP` for interface addresses. Any new code that touches config paths or interface lookups has to stay patchable the same way.

## Architecture

**Config loading (`UpdateDns.__init__`)**: config is read with `configparser` from `INI_PATHS` (in order: `<package dir>/updatedns.ini`, `/etc/updatedns.ini`, `~/.updatedns.ini`), then `--ini <path>`. Later files override earlier ones. Two settings make repeated keys work:
- `strict=False`
- the custom `MultiDict` dict type

Together they let a repeated `domain =` key accumulate into a single newline-joined value. `optionxform = str` keeps keys case-sensitive, so they pass straight through as driver kwargs.

**Section dispatch**: each section is one of two kinds, depending on its name.
- **Provider section**: the name, upper-cased, matches an attribute of `libcloud.dns.types.Provider` (for example `[route53]` becomes `Provider.ROUTE53`). Every key except `domain` goes to the libcloud driver constructor as a kwarg (`key`, `secret`, and so on). The set of supported providers depends on the installed libcloud version.
- **Host section**: any other section is treated as an FQDN and must have `interface = <ifname>`. Two booleans, `ipv4` (default yes) and `ipv6` (default no), pick which record types it gets. These sections are used only by `--monitor`.

**State built at startup (`enumerate`)**: on every run, the tool lists all zones for every provider and then all A and AAAA records in the configured zones, building these structures:
- `self.domains[domain] = [driver, zone]`: the driver is set during config parsing and the zone is appended during enumeration. A configured domain that the provider doesn't return as a zone has no zone entry. Startup logs a warning for it, and `_find_driver` raises `ValueError`.
- `self.records[(fqdn, record_type)] = Record`: only types in `ADDRESS_LOOKUP` (A and AAAA) are kept. The apex `@` or empty name maps to the bare domain.
- `self.zones[provider]`: every zone the provider has, used by `--zones`, which marks configured zones with `*`.

**Operations**:
- `set` picks A or AAAA from the address family, compares addresses with `ipaddress` (so differently written IPv6 text isn't treated as a change), and creates or updates the record.
- `delete` removes both the A and the AAAA record for a name.
- `_find_driver` maps an FQDN to its zone by checking whether it is a configured domain or ends with `.` plus one, and the longest match wins.

`--list <domain...>` limits which providers and domains are loaded at all.

**Errors and logging**:
- Everything logs through the `updatedns` logger: warnings by default, `-v` adds INFO (changes), and `-vv` adds DEBUG. `main` raises only that logger's level, so libcloud and urllib3 stay quiet.
- Recoverable failures (provider API errors, unknown hosts, interface lookup failures) go through `_error`, which logs and increments `self.errors`. `main` returns 1 if there were any.
- A `ValueError` that escapes an operation is reported by `main` as a fatal error, also with exit status 1.
- Only `--list` and `--zones` print to stdout.

**Monitor mode**: this is a loop that runs every 60 seconds, or a single pass with `--once`. It looks up each interface's address once per record type through `ADDRESS_LOOKUP`, then calls `set` for each host on that interface. Both lookups work only on Linux:
- `ipv4_address` uses the `SIOCGIFADDR` ioctl.
- `ipv6_address` parses `/proc/net/if_inet6`. It skips temporary, deprecated, tentative and DAD-failed addresses, and anything that isn't `is_global` (link-local, ULA, documentation ranges).

A failed lookup logs an error and skips only the records that need that address.

**Deployment files** (in `updatedns/`, shipped as package data, installation documented in the README): every hook runs `updatedns --monitor --once --verbose` and pipes its output to `logger -t updatedns`.
- `updatedns.service`: a systemd unit that runs `updatedns --monitor --verbose` after `network-online.target`, with `Restart=on-failure`.
- `updatedns-nm-dispatcher`: a NetworkManager dispatcher script.
- `updatedns-networkd-dispatcher`: a networkd-dispatcher `routable.d` script.
- `updatedns-exit-hook`: a dhclient exit hook covering IPv4 and DHCPv6 lease changes. dhclient-script *sources* it, so it must never `exit` or return non-zero. It runs `updatedns` in the background.
- The hooks append `/usr/local/bin` to `PATH`, because their callers' `PATH` can leave out where pip installs the script.
