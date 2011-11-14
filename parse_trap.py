#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Created on Nov 4, 2011
Last modified Nov 14, 2011

@author: marco
'''

import sys
import fileinput
import re
import socket
import os
import subprocess
import datetime
from trapconfig import TrapConfig

conf_file = "%s/parse_trap.conf" % os.path.dirname(os.path.abspath(__file__))

status = {0: 'completed',
          1: 'ignored',
          2: 'processing',
          3: 'failed'}

def parse_re(t, d, l):
    """ parses trap lines associating traps details with traps{} keys """
    for i in d:
        try:
            # format: "oid(.*) message"
            m = re.search(i + '[^ ]* (.*)', l)
            if m:
                t[d[i]] = m.group(1)
        except TypeError:
            pass
    return t

def parse_trap():
    """ reads trap details """
    t = {}
    f = "%Y-%m-%d %H:%M:%S"
    t['timestamp'] = datetime.datetime.now().strftime(f)
    for line in fileinput.input():
        line = line.strip('\n')
        t = parse_re(t, traps, line)
    return t

def fix_format(t):
    """ nice output formatting a stuff like that """
    # uptime
    if 'uptime' in t:
        t['uptime'] = "%s days" % re.search('[\w ]+', t['uptime']).group(0)
    # sender ip
    t['sender_ip'] = re.search('.*->\[([0-9\.]*)\]', t['sender_ip']).group(1)
    try:
        socket.setdefaulttimeout(3)
        t['sender_fqdn'] = socket.gethostbyaddr(t['sender_ip'])[0]
    except Exception:
        if dbg:
            debug("Reverse DNS lookup failed for ip '%s'" % t['sender_ip'])
        t['sender_fqdn'] = t['sender_hostname'] = False
    # sender hostname
    if t['sender_fqdn']:
        for d in strip_domains:
            t['sender_hostname'] = t['sender_fqdn'].replace(d, "")
    return t

def fix_nsca_message(t):
    if 'if_desc' in t:
        return "%s [%s]" % (t['if_desc'], t['if_alias'])
    elif 'ospf_neighbour' in t:
        return "%s %s" % (t['ospf_neighbour'], t['ospf_neighbour_state'])
    elif 'bgp_peer_ip' in t:
        return "%s %s" % (t['bgp_peer_ip'], t['bgp_peer_state'])
    else:
        try:
            return t['genmessage']
        except KeyError:
            return ""

def ignore_trap(t):
    """ checks if a trap should be ignored """
    # list of traps to ignore
    if t['oid'] in ignore_oid:
        debug("Trap ignored because of matching 'ignore_oid' OID")
        return 1
    # bgp peers traps to ignore
    if 'bgp_peer_ip' in t:
        for i in ignore_bgp_ips:
            if i in t['bgp_peer_ip']:
                debug("Trap ignored because of matching 'ignore_bgp_ips' IP [%s]" % i)
                return 1
    return 2

def debug(msg):
    if log:
        logtofile(str(msg))
    if dbg:
        print("DEBUG: %s" % msg)

def logtofile(msg):
    try:
        f = open(logfile, "a")
        f.write(msg + "\n")
        f.close()
    except IOError:
        print("Can't open '%s' to append log lines, exiting." % logfile)
        sys.exit()

def init():
    # global config options
    global dbg
    global log
    global logfile
    global nsca_cmd
    global strip_domains
    global ignore_oid
    global ignore_bgp_ips
    global traps
    p = TrapConfig(conf_file).get_conf()
    if not p:
        dbg = True
        log = False
        debug(p)
        return False
    dbg = p['logging']['debug']
    log = p['logging']['log']
    logfile = p['logging']['logfile']
    nsca_cmd = p['general']['nsca_command']
    strip_domains = [d for d in p['general']['strip_domains'].split(',')]
    ignore_oid = [i for i in p['ignore']['traps'].split(',')]
    ignore_bgp_ips = [i for i in p['ignore']['bgp_ip'].split(',')]
    traps = p['traps']
    return True

def main():
    if not init():
        sys.exit()
    t = parse_trap()
    t = fix_format(t)
    t['status'] = ignore_trap(t)
    t['status_info'] = status[t['status']]
    if t['status'] == 1:
        debug(t)
        sys.exit()
    nsca_message = fix_nsca_message(t)
    # send trap to monitoring
    cmd = "echo -e \"%s\t%s\t%s\t%s\n\" | %s" % (t['sender_hostname'], \
          "SNMP Traps", 2, t['uptime'] + " " + t['oid'] + " " + nsca_message, nsca_cmd)
    # used to ignore stderr
    fnull = open(os.devnull, 'w')
    if subprocess.call(cmd, shell = True, stdout = fnull, stderr = fnull):
        t['status'] = 3
    else:
        t['status'] = 0
    fnull.close()
    t['status_info'] = status[t['status']]
    debug(t)

if __name__ == "__main__":
    sys.exit(main());

# EOF
