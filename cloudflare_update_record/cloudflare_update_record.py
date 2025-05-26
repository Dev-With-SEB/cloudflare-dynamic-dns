#!/usr/bin/env python3

# Based on https://gist.github.com/benkulbertis/fff10759c2391b6618dd
# Originally writen by va1entin
#     va1entin's [Repo]https://github.com/va1entin/tools/tree/master/cloudflare_update_record
#     va1entin's [blog post](https://valh.io/p/python-script-for-cloudflare-dns-record-updates-dyndns/) for more information and config instructions.


import re
import sys
import yaml
import logging
import argparse
import requests

__version__ = '0.2.0'


log_levels = {'crit': logging.CRITICAL, 'warn': logging.WARN, 'info': logging.INFO, 'debug': logging.DEBUG}
required_config_keys = ['read_token', 'edit_token', 'zone_name', 'record_name']


def setup_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Path to config file', default='cloudflare_update_record_config.yaml')
    parser.add_argument('-4', '--ipv4', help='Set IPv4 address', action='store_true')
    parser.add_argument('-6', '--ipv6', help='Set IPv6 address', action='store_true')
    parser.add_argument('-lc', '--local-cache', help='Compare current IP to IP last set according to local cache file cloudflare_update_record_ip<version>.txt', action='store_true')
    parser.add_argument('-f', '--force', help='Force setting IP address, if it is set already', action='store_true')
    parser.add_argument('-4p', '--ipv4-provider', help='Provider for IPv4 address', default='https://ipv4.icanhazip.com')
    parser.add_argument('-6p', '--ipv6-provider', help='Provider for IPv6 address', default='https://ipv6.icanhazip.com')
    parser.add_argument('-v', '--log-level', help=f'Log level, possible choices: {list(log_levels)}', default='info')
    parser.add_argument('-l', '--log-file', help='Log file', default='cloudflare_update_record.log')
    args = parser.parse_args()
    return args


def setup_logging(args):
    if args.log_level not in log_levels:
        logging.basicConfig(filename=args.log_file, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_levels['info'])
        logging.warning(f'Specified log level "{args.log_level}" is not allowed, see output of -h for possible values')
    else:
        logging.basicConfig(filename=args.log_file, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_levels[args.log_level])
        logging.debug(f'Set log level "{args.log_level}"')


def get_ip(version, args):
    if version == 4:
        try:
            request_successful, response = make_request('get', args.ipv4_provider)
        except:
            logging.exception(f'Could not connect to {args.ipv4_provider} with IPv{version}')
            return False
    elif version == 6:
        try:
            request_successful, response = make_request('get', args.ipv6_provider)
        except:
            logging.exception(f'Could not connect to {args.ipv6_provider} with IPv{version}')
            return False
    if request_successful:
        ip = re.sub(r'\n', '', response.text)
        return ip
    else:
        if version == 4:
            logging.critical(f'Unsuccessful request; current IPv{version} address could not be obtained from {args.ipv4_provider}, dumping response:\n{response.content}')
        elif version == 6:
            logging.critical(f'Unsuccessful request; current IPv{version} address could not be obtained from {args.ipv6_provider}, dumping response:\n{response.content}')
        return False


def make_request(kind, url, headers=None, data=None, exit_on_fail=False):
    if kind == 'get':
        response = requests.get(url, headers=headers, data=data)
    elif kind == 'put':
        response = requests.put(url, headers=headers, data=data)

    if response.status_code == 200:
        return True, response
    else:
        logging.critical(f'{kind} request failed: {url}\n{response.content}')
        if exit_on_fail:
            sys.exit(1)
        return False, response


def check_ip(current_ip_address, version):
    try:
        with open(f'cloudflare_update_record_ip{version}.txt', 'r', encoding='UTF-8') as f:
            old_ip = f.read()
        if current_ip_address == old_ip:
            return False
        else:
            return True
    except FileNotFoundError:
        logging.info(f'Could not find file cloudflare_update_record_ip{version}.txt, continuing...')
        return True

def check_config(config, config_file):
    for required_config_key in required_config_keys:
        if required_config_key not in config:
            logging.critical(f'Required config key "{required_config_key}" missing in config "{config_file}"! Exiting...')
            sys.exit(1)

    # Normalize record_name to a list
    if isinstance(config["record_name"], str):
        config["record_name"] = [config["record_name"]]
    elif not isinstance(config["record_name"], list):
        logging.critical(f'"record_name" in config must be a string or a list of strings. Got: {type(config["record_name"])}')
        sys.exit(1)

    for i, record in enumerate(config["record_name"]):
        if record.endswith(config["zone_name"]):
            logging.warning(f'record_name "{record}" in config "{config_file}" contains zone_name "{config["zone_name"]}". This is not necessary and should be removed.')
            config["record_name"][i] = re.sub(f'.{config["zone_name"]}$', '', record)


def get_config(config_file):
    try:
        with open(config_file, 'r', encoding='UTF-8') as stream:
            config = yaml.safe_load(stream)
        logging.debug(f'Config:\n{config}')
        return config
    except FileNotFoundError:
        logging.critical(f'Could not find config file at {config_file} - exiting...')
        sys.exit(1)


def get_identifiers(config, record_type, record_name):
    request_successful, zone_id_response = make_request(
        'get',
        f'https://api.cloudflare.com/client/v4/zones?name={config["zone_name"]}',
        headers={"Authorization": f"Bearer {config['read_token']}", "Content-Type": "application/json"},
        exit_on_fail=True
    )
    zone_identifier = zone_id_response.json()['result'][0]['id']

    fqdn = config["zone_name"] if record_name == "@" else f'{record_name}.{config["zone_name"]}'
    request_successful, record_id_response = make_request(
        'get',
        f'https://api.cloudflare.com/client/v4/zones/{zone_identifier}/dns_records?name={fqdn}&type={record_type}',
        headers={"Authorization": f"Bearer {config['read_token']}", "Content-Type": "application/json"},
        exit_on_fail=True
    )

    try:
        record_identifier = record_id_response.json()['result'][0]['id']
        record_ip = record_id_response.json()['result'][0]['content']
    except IndexError:
        logging.exception(f'Could not find id of DNS record "{fqdn}". Please ensure it exists in Cloudflare. Check config file "{args.config}".')
        sys.exit(1)

    return zone_identifier, record_identifier, record_ip



def update_record(config, ip, record_type, zone_identifier, record_identifier, record_name):
    request_successful, response = make_request(
        'put',
        f'https://api.cloudflare.com/client/v4/zones/{zone_identifier}/dns_records/{record_identifier}',
        headers={"Authorization": f"Bearer {config['edit_token']}", "Content-Type": "application/json"},
        data=f'{{"id": "{zone_identifier}", "type": "{record_type}", "name": "{record_name}","content": "{ip}"}}'
    )

    if request_successful:
        logging.info(f'DNS {record_type} record "{record_name}" update succeeded. IP changed to: "{ip}"')
    else:
        logging.critical(f'DNS {record_type} record "{record_name}" update failed, dumping API response:\n{response.content}')
        sys.exit(1)



def write_ip(ip, version):
    logging.debug(f'Writing IPv{version} address to file: {ip}')
    with open(f'cloudflare_update_record_ip{version}.txt', 'w', encoding='UTF-8') as f:
        f.write(ip)


def main(ip_version, record_type, args):
    current_ip_address = get_ip(ip_version, args)
    if not current_ip_address:
        return

    if args.local_cache:
        ip_different = check_ip(current_ip_address, ip_version)
    else:
        ip_different = True

    if not ip_different:
        logging.info(f'IPv{ip_version} address has not changed. Exiting...')
        return

    config = get_config(args.config)
    check_config(config, args.config)

    for record_name in config["record_name"]:
        zone_identifier, record_identifier, record_ip = get_identifiers(config, record_type, record_name)

        if current_ip_address != record_ip:
            update_record(config, current_ip_address, record_type, zone_identifier, record_identifier, record_name)
            write_ip(current_ip_address, ip_version)
        elif args.force:
            logging.warning(f'Force parameter is set. Forcing IP address "{current_ip_address}" update for record "{record_name}" even though it matches current record IP.')
            update_record(config, current_ip_address, record_type, zone_identifier, record_identifier, record_name)
            write_ip(current_ip_address, ip_version)
        else:
            logging.info(f'IPv{ip_version} address "{current_ip_address}" already matches DNS record "{record_name}". Skipping...')


if __name__ == '__main__':
    args = setup_parser()
    setup_logging(args)
    if not args.ipv4 and not args.ipv6:
        logging.critical('Neither -4 nor -6 parameter is set - exiting...')
        sys.exit(1)
    if args.ipv4:
        main(4, 'A', args)
    if args.ipv6:
        main(6, 'AAAA', args)