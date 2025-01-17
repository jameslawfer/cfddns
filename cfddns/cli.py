#!/usr/bin/env python3
# based on examples/example_update_dynamic_dns.py
# at https://github.com/cloudflare/python-cloudflare

import asyncio
import re
import time
import logging
from datetime import datetime

import click
import CloudFlare
import requests
import yaml
import time

from .notification import send_notification


def get_ip_address(endpoint):
    try:
        retry_count = 3
        logging.debug("retry_count = %d" %retry_count)
        while retry_count > 0:
            res = requests.get(endpoint)
            if res.status_code == 200:
                ip_address = res.text.strip()
                logging.debug("WAN IP successfully retrieved")
                break
            retry_count -= 1
            logging.warning("WAN IP retrieval endpoint returned HTTP %s response status code" % res.status_code)
            time.sleep(5)

        if retry_count == 0:
            logging.error("%s is unreachable at this time" % endpoint)
            return

    # General exception, will be thrown if no connectivity to endpoint
    except Exception:
        logging.error("IP address retrieval from %s failed" % endpoint)
        return

    if ip_address == '':
        logging.error("IP address retrieval from %s failed (API returned NULL)" % endpoint)
        return

    if ':' in ip_address:
        ip_address_type = 'AAAA'
    else:
        ip_address_type = 'A'

    return ip_address, ip_address_type


def update_record(cf, zone_id, dns_name, dns_config, ip_address, ip_address_type):
    params = {'name': dns_name, 'match': 'all', 'type': ip_address_type}

    proxied = dns_config.get('proxied')

    try:
        dns_records = cf.zones.dns_records.get(zone_id, params=params)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        exit('/zones/dns_records %s - %s - api call failed' % (dns_name, e))
    logging.debug("dns_records: %s" % dns_records)
    updated = False
    should_inform = False

    for dns_record in dns_records:
        old_ip_address = dns_record['content']
        old_ip_address_type = dns_record['type']
        dns_record_id = dns_record['id']
        old_proxied = dns_record['proxied']

        if ip_address_type not in ['A', 'AAAA']:
            # won't this always be false as ip_address_type is set in get_ip_address() with only these options
            continue

        if ip_address_type != old_ip_address_type:
            logging.warning("IP address change ignored: %s \t%s - Wrong address family" % (dns_name, ip_address))
            should_inform = True
            continue

        if ((ip_address == old_ip_address) and (proxied == old_proxied)):
            logging.info("DNS record unchanged: {:<26s} {:<34s} | Proxied: {:<14s}".format(dns_name, ip_address, str(proxied)))
            updated = True
            continue

        dns_record = {
            'name': dns_name,
            'type': ip_address_type,
            'content': ip_address,
            'proxied': proxied
        }
        try:
            dns_record = cf.zones.dns_records.put(zone_id,
                                                  dns_record_id,
                                                  data=dns_record)
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            logging.error("/zones.dns_records.put %s %s - API call failed" % (dns_name, e))
            return True
        logging.info("DNS record updated:   {:<26s} {:<15s} -> {:<15s} | Proxied: {:<5s} -> {:<5s}".format(dns_name, old_ip_address, ip_address, str(old_proxied), str(proxied)))
        updated = True
        should_inform = True

    if updated:
        return should_inform

    should_inform = True

    # no exsiting dns record to update - so create dns record
    dns_record = {
        'name': dns_name,
        'type': ip_address_type,
        'content': ip_address,
        'proxied': proxied
    }
    try:
        dns_record = cf.zones.dns_records.post(zone_id, data=dns_record)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        logging.error("/zones.dns_records.post %s %s - API call failed" % (dns_name, e))
        return True
    logging.info("DNS record created:   {:<26s} {:<34s} | Proxied: {:<14s}".format(dns_name, ip_address, str(proxied)))
    return should_inform


def update_domain(dns_name, dns_config, ip_address, ip_address_type, token):
    zone_name = re.compile("\.(?=.+\.)").split(dns_name)[-1]
    logging.debug("zone_name (regex from dns_name): %s" % zone_name)
    # print('pending: %s' % dns_name)

    cf = CloudFlare.CloudFlare(token=token)

    try:
        params = {'name': zone_name}
        zones = cf.zones.get(params=params)
        #logging.debug("/zones.get: %s" % zones)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        logging.error("/zones '%s' - API call failed. Check if API token is set and configured correctly" % e)
        return True
    except Exception as e:
        logging.error("/zones.get '%s' - API call failed." % e)
        return True

    # Correct zone was not found
    if len(zones) == 0:
        logging.error("/zones.get '%s' - Zone not found. Check if API token is configured to include your relevant zone resources" % zone_name)
        return True

    if len(zones) != 1:
        logging.error("/zones.get '%s' - API call returned too many or too few zone items (!=1)" % zone_name)
        return True

    zone = zones[0]

    zone_name = zone['name']
    zone_id = zone['id']
    logging.debug("zone_name: %s zone_id: %s" % (zone_name, zone_id))

    return update_record(cf,
                         zone_id,
                         dns_name,
                         dns_config,
                         ip_address,
                         ip_address_type)


def update(domains_config, token, endpoint):
    logging.info("Checking for WAN IP updates at %s" % datetime.now())

    ip = get_ip_address(endpoint)
    if ip is None:
        return True

    ip_address, ip_address_type = ip
    logging.info("WAN IP: %s" % ip_address)
    logging.debug("ip_address_type: %s" % ip_address_type)

    should_inform = False
    for dns_name in domains_config:
        dns_config = domains_config[dns_name]
        logging.debug("dns_name: %s \tdns_config: %s" % (dns_name, dns_config))
        changed = update_domain(dns_name,
                                dns_config,
                                ip_address,
                                ip_address_type,
                                token=token)
        should_inform = should_inform | changed

    logging.info("Finished update cycle at %s" % datetime.now())
    return should_inform


@click.command()
@click.argument('domains',
                type=click.File('r'))
@click.option('--config',
              '-c',
              type=click.File('r'),
              help='Path to config file (YAML)',
              required=True)
@click.option('--debug',
              '-d',
              help='Turn debug logging on',
              is_flag=True,
              default=False)
@click.option('--proxy/--no-proxy',
              help='Set default proxy value',
              is_flag=True,
              default=True)

def main(domains, config, debug, proxy):
    # Setup logging
    if (debug):
        logging.basicConfig(level=logging.DEBUG,
                format = "<%(levelname).4s> %(module)s>>%(funcName)s() :: %(message)s")
    else:
        logging.basicConfig(level = logging.INFO,
                format = "%(message)s")

    logging.info("cfddns (CloudFlare Dynamic DNS) vX.X.X\n")
    logging.debug("Debug enabled")
    logging.debug("Default proxy value -> %s" % proxy)

    time.tzset()

    logging.warning("WARNING test")
    logging.info("INFO test")

    conf = yaml.full_load(config)
    interval = conf.get('interval', 600)
    endpoint = conf.get('endpoint', "https://api.ipify.org")
    token = conf['token']

    notification_enabled = False
    notification_conf = conf.get('notification', None)
    if notification_conf:
        mail_from = notification_conf.get('from')
        mail_to = notification_conf.get('to')
        notification_enabled = notification_conf.get('enabled', False)

    logging.info("Update interval: %s seconds" % interval)
    logging.info("Endpoint: %s" % endpoint)

    # Parse and clean up domains.yml configuration file
    domains_config = yaml.full_load(domains)
    for domain in domains_config:
        #logging.debug("Parsing domain: %s" % domain)
        if domains_config[domain]:
            logging.debug("Domain configuration found for %s -> %s" % (domain, domains_config[domain]))
            if 'proxied' in domains_config[domain]:
                logging.debug("Proxy setting found for %s -> %s" % (domain, domains_config[domain].get('proxied')))
                if ((domains_config[domain].get('proxied') == True) or (domains_config[domain].get('proxied') == False)):
                    logging.debug("Proxy setting for %s is valid -> %s" % (domain, domains_config[domain].get('proxied')))
                else:
                    logging.debug("Proxy setting for %s is invalid, setting to default value" % domain)
                    # set proxy default
                    domains_config[domain]['proxied'] = proxy
                    logging.debug("Proxy setting for %s changed -> %s" % (domain, domains_config[domain].get('proxied')))
            else:
                logging.debug("No proxy setting found for %s" % domain)
                # set proxy default
                domains_config[domain]['proxied'] = proxy
                logging.debug("Proxy setting for %s created -> %s" % (domain, domains_config[domain].get('proxied')))
        else:
            logging.debug("No domain configuration found for %s" % domain)
            # set proxy default
            domains_config[domain] = {'proxied': proxy}
            logging.debug("Proxy setting for %s created -> %s" % (domain, domains_config[domain].get('proxied')))

    log_buffer = []

    def logger(text):
        log_buffer.append(text)
        print(text, flush=True)

    async def wrapper():
        while True:
            should_inform = update(domains_config, token, endpoint)
            if should_inform and notification_enabled:
                # Broke notifications due to use of logging module
                log = "\n".join(log_buffer)
                send_notification(mail_from, mail_to, "cfddns", log)
            log_buffer.clear()
            await asyncio.sleep(interval)

    asyncio.run(wrapper())
