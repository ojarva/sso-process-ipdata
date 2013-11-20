import subprocess
import redis
import time
from config import Config
import socket
import geoip2
import geoip2.models
import geoip2.database
import ipaddr
import sys
from instrumentation import *

socket.setdefaulttimeout(5)

from local_settings import IP_NETWORKS

class ProcessIP:
    def __init__(self, ip_addr, redis_instance):
        self.geo = geoip2.database.Reader("GeoLite2-City.mmdb")
        self.ip_addr = ip_addr
        self._ip = ipaddr.IPv4Address(self.ip_addr)
        self.redis = redis_instance

    def fetch(self):
        """ Fetches all (DNS/geoip/whois) information for the address """
        statsd.incr("ipdb.fetch")
        self.fetch_dns()
        self.fetch_geoip()
        self.fetch_ip_whois()
        hostname = self.redis.get("ipdb-reverse-for-%s" % self.ip_addr)
        if hostname and not self.is_local_address():
            self.fetch_dns_whois(hostname)

    def fetch_dns(self):
        """ Fetch reverse DNS information (hostname) """
        statsd.incr("ipdb.fetch_dns")
        try:
            hostname = socket.gethostbyaddr(self.ip_addr)
        except:
            return
        self.redis.set("ipdb-reverse-for-%s" % self.ip_addr, hostname[0])
        self.redis.set("ipdb-reverse-for-%s-timestamp" % self.ip_addr, time.time())
        try:
            ip_for_hostname = socket.gethostbyname(hostname[0])
        except:
            return

        if ip_for_hostname == self.ip_addr:
            self.redis.set("ipdb-reverse-for-%s-valid" % self.ip_addr, True)
        else:
            self.redis.set("ipdb-reverse-for-%s-valid" % self.ip_addr, False)

    def is_local_address(self):
        """ Returns True, if the address is reserved/private/local/multicast"""
        status = (self._ip.is_link_local or 
                 self._ip.is_multicast or
                 self._ip.is_reserved or
                 self._ip.is_private)
        if status:
            statsd.incr("ipdb.local_address")
        else:
            statsd.incr("ipdb.real_address")
        return status

    def is_private_net(self):
        """ Returns True if specified in private networks, imported from
            local_settings """
        for (network, country, city, description) in IP_NETWORKS:
            if ((isinstance(network, ipaddr.IPv4Address) and 
                self._ip is network) or 
               (isinstance(network, ipaddr.IPv4Network) and 
                self._ip in network)):
                self.redis.set("ipdb-city-for-ip-%s" % self.ip_addr, city)
                self.redis.set("ipdb-country-for-ip-%s" % self.ip_addr, country)
                self.redis.set("ipdb-description-for-ip-%s" % self.ip_addr, description)
                self.redis.set("ipdb-at-office-ip-%s" % self.ip_addr, True)
                statsd.incr("ipdb.futurice_address")
                return True
        statsd.incr("ipdb.external_address")
        return False

    @timing("ipdb.fetch_geoip")
    def fetch_geoip(self):
        """ Fetch geoip information, if not local address """
        if self.is_local_address():
            return
        statsd.incr("ipdb.fetch_geoip")
        city = self.geo.city(self.ip_addr)
        self.redis.set("ipdb-country-for-ip-%s" % self.ip_addr,  city.country.iso_code)
        if city.city.name:
            statsd.incr("ipdb.fetch_geoip.city")
            self.redis.set("ipdb-city-for-ip-%s" % self.ip_addr,  city.city.name)

    def fetch_ip_whois(self):
        """ Fetch whois information for IP, if not available from redis """
        if self.is_private_net():
            return
        if self.is_local_address():
            return
        if self.redis.exists("ipdb-whois-for-ip-%s" % self.ip_addr):
            return
        self._fetch_ip_whois()

    @timing("ipdb.fetch_ip_whois")
    def _fetch_ip_whois(self):
        statsd.incr("ipdb.fetch_ip_whois")
        proc = subprocess.Popen(["whois", self.ip_addr], stdout=subprocess.PIPE)
        (data, _) = proc.communicate()
        self.redis.set("ipdb-whois-for-ip-%s" % self.ip_addr, data)
        self.redis.set("ipdb-whois-for-ip-%s-timestamp" % self.ip_addr, time.time())

    def fetch_dns_whois(self, hostname):
        """ Fetch whois information for domain, if not available from redis"""
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


@timing("ipdb.update.main")
def process(redis_instance):
    """ Process queue indefinitely """
    #lpop is blocking call
    ip_addr = redis_instance.lpop("ip-resolve-queue")
    while ip_addr:
        ipdata = ProcessIP(ip_addr, redis_instance)
        ipdata.fetch()
        ip_addr = redis_instance.lpop("ip-resolve-queue")

def main(args):
    """ If the first item in args list is "daemon", loop over process()."""
    config = Config()
    redis_instance = redis.Redis(host=config.get("redis-hostname"), 
            port=config.get("redis-port"), db=config.get("redis-db"))
    if isinstance(args, list) and len(args) > 1:
        if args[1] == "daemon":
            while True:
                process(redis_instance)
                time.sleep(5)
    process(redis_instance)

if __name__ == '__main__':
    main(sys.argv)
