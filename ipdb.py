import subprocess
import redis
import time
import re
from config import Config
import socket
import geoip2
import geoip2.models
import geoip2.database
import ipaddr
import sys
from instrumentation import *

socket.setdefaulttimeout(5)

geo = geoip2.database.Reader("GeoLite2-City.mmdb")
from local_settings import IP_NETWORKS

class IPdbUpdate:
    def __init__(self):
        self._db = None
        self.config = Config()
        self.redis = redis.Redis(host=self.config.get("redis-hostname"), port=self.config.get("redis-port"), db=self.config.get("redis-db"))

    @timing("ipdb.update.main")
    def process(self):
        #lpop is blocking call
        ip_addr = self.redis.lpop("ip-resolve-queue")
        while ip_addr:
            self.fetch(ip_addr)
            ip_addr = self.redis.lpop("ip-resolve-queue")

    def fetch(self, ip_addr):
        statsd.incr("ipdb.fetch")
        self.fetch_dns(ip_addr)
        self.fetch_geoip(ip_addr)
        self.fetch_ip_whois(ip_addr)
        hostname = self.redis.get("ipdb-reverse-for-%s" % ip_addr)
        if hostname and not self.is_local_address(ip_addr):
            self.fetch_dns_whois(hostname)

    def fetch_dns(self, ip_addr):
        statsd.incr("ipdb.fetch_dns")
        try:
            hostname = socket.gethostbyaddr(ip_addr)
        except:
            return
        self.redis.set("ipdb-reverse-for-%s" % ip_addr, hostname[0])
        self.redis.set("ipdb-reverse-for-%s-timestamp" % ip_addr, time.time())
        try:
            ip_for_hostname = socket.gethostbyname(hostname[0])
        except:
            return

        if ip_for_hostname == ip_addr:
            self.redis.set("ipdb-reverse-for-%s-valid" % ip_addr, True)
        else:
            self.redis.set("ipdb-reverse-for-%s-valid" % ip_addr, False)

    def is_local_address(self, ip_addr):
        _ip = ipaddr.IPv4Address(ip_addr)
        status =  _ip.is_link_local or _ip.is_multicast or _ip.is_reserved or _ip.is_private
        if status:
            statsd.incr("ipdb.local_address")
        else:
            statsd.incr("ipdb.real_address")
        return status

    def is_futurice_net(self, ip_addr):
        _ip = ipaddr.IPv4Address(ip_addr)
        for (network, country, city, description) in IP_NETWORKS:
            if (isinstance(network, ipaddr.IPv4Address) and _ip is network) or (isinstance(network, ipaddr.IPv4Network) and _ip in network):
                self.redis.set("ipdb-city-for-ip-%s" % ip_addr, city)
                self.redis.set("ipdb-country-for-ip-%s" % ip_addr, country)
                self.redis.set("ipdb-description-for-ip-%s" % ip_addr, description)
                self.redis.set("ipdb-at-office-ip-%s" % ip_addr, True)
                statsd.incr("ipdb.futurice_address")
                return True
        statsd.incr("ipdb.external_address")
        return False

    @timing("ipdb.fetch_geoip")
    def fetch_geoip(self, ip_addr):
        if self.is_local_address(ip_addr):
            return
        statsd.incr("ipdb.fetch_geoip")
        city = geo.city(ip_addr)
        self.redis.set("ipdb-country-for-ip-%s" % ip_addr,  city.country.iso_code)
        if city.city.name:
            statsd.incr("ipdb.fetch_geoip.city")
            self.redis.set("ipdb-city-for-ip-%s" % ip_addr,  city.city.name)

    def fetch_ip_whois(self, ip_addr):
        if self.is_futurice_net(ip_addr):
            return
        if self.is_local_address(ip_addr):
            return
        if self.redis.exists("ipdb-whois-for-ip-%s" % ip_addr):
            return
        self._fetch_ip_whois(ip_addr)

    @timing("ipdb.fetch_ip_whois")
    def _fetch_ip_whois(self, ip_addr):
        statsd.incr("ipdb.fetch_ip_whois")
        proc = subprocess.Popen(["whois", ip_addr], stdout=subprocess.PIPE)
        (data, _) = proc.communicate()
        self.redis.set("ipdb-whois-for-ip-%s" % ip_addr, data)
        self.redis.set("ipdb-whois-for-ip-%s-timestamp" % ip_addr, time.time())

    def fetch_dns_whois(self, hostname):
        hostname = hostname.split(".")
        hostname = ".".join(len(hostname[-2]) < 4 and hostname[-3:] or hostname[-2:])
        if self.redis.exists("ipdb-whois-for-domain-%s" % hostname):
            return
        self._fetch_dns_whois(hostname)

    @timing("ipdb.fetch_dns_whois")
    def _fetch_dns_whois(self, hostname):
        statsd.incr("ipdb.fetch_dns_whois")
        proc = subprocess.Popen(["whois", hostname], stdout=subprocess.PIPE)
        (data, _) = proc.communicate()
        self.redis.set("ipdb-whois-for-domain-%s" % hostname, data)
        self.redis.set("ipdb-whois-for-domain-%s-timestamp" % hostname, time.time())


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def main(args):
    ipdb = IPdbUpdate()
    if len(args) > 1:
        if args[1] == "daemon":
            while True:
                ipdb.process()
                time.sleep(5)
    ipdb.process()

if __name__ == '__main__':
    main(sys.argv)
