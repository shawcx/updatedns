import types

import pytest

import libcloud.dns.providers
from updatedns import updatedns


INI = '''
[route53]
key    = AKID
secret = s3cret
domain = example.com
domain = sub.example.com
domain = missing.org

[host.example.com]
interface = eth0

[v6.example.com]
interface = eth0
ipv4      = no
ipv6      = yes

[both.example.com]
interface = wan0
ipv6      = yes

[nointerface.example.com]
ipv6 = yes
'''


class Zone:
    def __init__(self, domain):
        self.domain = domain


class Record:
    def __init__(self, name, type, data, zone):
        self.name = name
        self.type = type
        self.data = data
        self.zone = zone


class FakeDriver:
    def __init__(self):
        self.credentials = None
        self.fail = False
        self.zones = [Zone('example.com.'), Zone('sub.example.com.'), Zone('unconfigured.net.')]
        self.records = []

    def add(self, name, type, data, zone=0):
        record = Record(name, type, data, self.zones[zone])
        self.records.append(record)
        return record

    def _check(self):
        if self.fail:
            raise RuntimeError('API down')

    def list_zones(self):
        self._check()
        return self.zones

    def list_records(self, zone):
        return [record for record in self.records if record.zone is zone]

    def create_record(self, name, zone, type, data):
        self._check()
        return self.add(name, type, data, self.zones.index(zone))

    def update_record(self, record, data):
        self._check()
        self.records.remove(record)
        return self.add(record.name, record.type, data, self.zones.index(record.zone))

    def delete_record(self, record):
        self._check()
        self.records.remove(record)


@pytest.fixture
def driver(tmp_path, monkeypatch):
    path = tmp_path / 'updatedns.ini'
    path.write_text(INI)
    # never read the real /etc or ~ config during tests
    monkeypatch.setattr(updatedns, 'INI_PATHS', [str(path)])

    driver = FakeDriver()
    driver.add('www', 'A', '192.0.2.1')
    driver.add('@', 'A', '192.0.2.2')
    driver.add('www', 'AAAA', '2001:db8::1')
    driver.add('www', 'MX', 'mail.example.com.')
    driver.add('x', 'A', '192.0.2.3', zone=1)

    def get_driver(provider):
        def factory(**credentials):
            driver.credentials = credentials
            return driver
        return factory
    monkeypatch.setattr(libcloud.dns.providers, 'get_driver', get_driver)
    return driver


def make(**kwargs):
    args = types.SimpleNamespace(ini=None, list=None, verbose=0)
    vars(args).update(kwargs)
    return updatedns.UpdateDns(args)


def data(driver, name, type):
    return [record.data for record in driver.records if record.name == name and record.type == type]


def test_config(driver, caplog):
    dns = make()
    assert driver.credentials == {'key': 'AKID', 'secret': 's3cret'}
    assert set(dns.domains) == {'example.com', 'sub.example.com', 'missing.org'}
    assert dns.interfaces == {
        'eth0': [('host.example.com', ['A']), ('v6.example.com', ['AAAA'])],
        'wan0': [('both.example.com', ['A', 'AAAA'])],
        }
    assert 'Missing interface from host nointerface.example.com' in caplog.text
    assert 'Zone not found at provider: missing.org' in caplog.text


def test_enumerate(driver):
    dns = make()
    assert set(dns.records) == {
        ('www.example.com', 'A'),
        ('example.com', 'A'),
        ('www.example.com', 'AAAA'),
        ('x.sub.example.com', 'A'),
        }
    assert dns.zones['ROUTE53'] == ['example.com', 'sub.example.com', 'unconfigured.net']
    assert dns.errors == 0


def test_enumerate_provider_failure(driver):
    driver.fail = True
    dns = make()
    assert dns.records == {}
    assert dns.errors == 1


@pytest.mark.parametrize('fqdn,zone,name', [
    ('www.example.com', 0, 'www'),
    ('example.com', 0, ''),
    ('x.sub.example.com', 1, 'x'),
    ])
def test_find_driver(driver, fqdn, zone, name):
    assert make()._find_driver(fqdn) == (driver, driver.zones[zone], name)


@pytest.mark.parametrize('fqdn,message', [
    ('foo.notexample.com', 'Unknown domain'),
    ('host.missing.org', 'Zone not found at provider: missing.org'),
    ])
def test_find_driver_errors(driver, fqdn, message):
    with pytest.raises(ValueError, match=message):
        make()._find_driver(fqdn)


def test_set_create(driver):
    dns = make()
    dns.set('new.example.com', '198.51.100.1')
    dns.set('new.example.com', '2001:db8::99')
    assert data(driver, 'new', 'A') == ['198.51.100.1']
    assert data(driver, 'new', 'AAAA') == ['2001:db8::99']
    assert dns.errors == 0


def test_set_update(driver):
    dns = make()
    dns.set('www.example.com', '198.51.100.1')
    assert data(driver, 'www', 'A') == ['198.51.100.1']
    assert data(driver, 'www', 'AAAA') == ['2001:db8::1']


def test_set_no_change(driver):
    dns = make()
    driver.fail = True
    # same address in a different textual form must not count as a change
    dns.set('www.example.com', '2001:0db8:0000::0001')
    assert dns.errors == 0


def test_set_invalid_address(driver):
    with pytest.raises(ValueError, match='Invalid address'):
        make().set('www.example.com', 'not-an-ip')


def test_set_failure(driver):
    dns = make()
    driver.fail = True
    dns.set('www.example.com', '198.51.100.1')
    dns.set('new.example.com', '198.51.100.1')
    assert dns.errors == 2
    assert dns.records[('www.example.com', 'A')].data == '192.0.2.1'


def test_delete(driver):
    dns = make()
    dns.delete(['www.example.com', 'nope.example.com'])
    assert data(driver, 'www', 'A') == []
    assert data(driver, 'www', 'AAAA') == []
    assert data(driver, 'www', 'MX') == ['mail.example.com.']
    assert dns.errors == 1


def test_monitor_once(driver, monkeypatch):
    def ipv4_address(ifname):
        if ifname != 'eth0':
            raise OSError('no such device')
        return '198.51.100.7'
    monkeypatch.setitem(updatedns.ADDRESS_LOOKUP, 'A', ipv4_address)
    monkeypatch.setitem(updatedns.ADDRESS_LOOKUP, 'AAAA', lambda ifname: '2001:db8::7')

    dns = make()
    dns.monitor(once=True)
    assert data(driver, 'host', 'A') == ['198.51.100.7']
    assert data(driver, 'v6', 'AAAA') == ['2001:db8::7']
    assert data(driver, 'v6', 'A') == []
    # wan0 has no IPv4 address, but its IPv6 record is still set
    assert data(driver, 'both', 'A') == []
    assert data(driver, 'both', 'AAAA') == ['2001:db8::7']
    assert dns.errors == 1


IF_INET6 = '''\
00000000000000000000000000000001 01 80 10 80       lo
fe800000000000002ef05dfffe606ef2 02 40 20 80     eth0
2a001450400182a00000000000000001 02 40 00 01     eth0
fd000000000000000000000000000001 02 40 00 80     eth0
2a001450400182a00000000000000002 02 40 00 20     eth0
2a001450400182a00000000000000003 02 40 00 00     eth0
2a001450400182a00000000000000004 03 40 00 00     eth1
'''

def test_ipv6_address(tmp_path):
    path = tmp_path / 'if_inet6'
    path.write_text(IF_INET6)
    # skips link-local, temporary, ULA and deprecated addresses
    assert updatedns.ipv6_address('eth0', path) == '2a00:1450:4001:82a0::3'
    assert updatedns.ipv6_address('eth1', path) == '2a00:1450:4001:82a0::4'
    with pytest.raises(LookupError):
        updatedns.ipv6_address('lo', path)


def test_main_exit_codes(driver, monkeypatch):
    monkeypatch.setitem(updatedns.ADDRESS_LOOKUP, 'A', lambda ifname: '198.51.100.7')
    monkeypatch.setitem(updatedns.ADDRESS_LOOKUP, 'AAAA', lambda ifname: '2001:db8::7')
    assert updatedns.main(['--monitor', '--once']) == 0
    assert updatedns.main(['--name', 'foo.notexample.com', '--addr', '198.51.100.1']) == 1
    assert updatedns.main(['--delete', 'nope.example.com']) == 1
    assert updatedns.main([]) == 1
