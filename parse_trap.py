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

def update_status(t, s):
    t['status'] = s
    t['status_info'] = status[t['status']]
    return t

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
    f = "%b %d %H:%M:%S %Y"
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
        m = "Reverse DNS lookup failed for ip \"%s\"" % t['sender_ip']
        t['sender_fqdn'] = t['sender_hostname'] = False
        t = update_status(t, 3)
        debug(m)
        logtofile(t, m)
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
            return t['genmessage'].strip('"')
        except KeyError:
            return ""

def ignore_trap(t):
    """ checks if a trap should be ignored """
    # list of traps to ignore
    if t['oid'] in ignore_oid:
        m = "Trap ignored because of matching \"ignore_oid\" OID"
        t = update_status(t, 1)
        debug(m)
        logtofile(t, m)
        return t
    # bgp peers traps to ignore
    if 'bgp_peer_ip' in t:
        for i in ignore_bgp_ips:
            if i in t['bgp_peer_ip']:
                m = "Trap ignored because of matching \"ignore_bgp_ips\" IP [%s]" % i
                t = update_status(t, 1)
                debug(m)
                logtofile(t, m)
                return t
    t = update_status(t, 2)
    return t

def debug(msg):
    if dbg:
        print("DEBUG: %s" % msg)

def logtofile(t, msg = False):
    if log:
        start = ['timestamp', 'sender_ip', 'uptime', 'oid', 'status_info']
        logbeg = ""
        for s in start:
            # general logfile structure
            logbeg += "%s " % t[s]
        try:
            f = open(logfile, "a")
            if msg:
                logline = "%s'%s'" % (logbeg, msg)
            else:
                # full data structure dump
                s = t.keys()
                start.reverse()
                for i in start:
                    s.remove(i)
                logline = logbeg
                for k in s:
                    logline += "'%s: %s' " % (k, t[k])
            f.write(logline + "\n")
            f.close()
        except IOError:
            dbg = True
            debug("Can't open \"%s\" to append log lines, exiting." % logfile)
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
    strip_domains = [d.strip() for d in p['general']['strip_domains'].split(',')]
    ignore_oid = [i.strip() for i in p['ignore']['traps'].split(',')]
    ignore_bgp_ips = [i.strip() for i in p['ignore']['bgp_ip'].split(',')]
    traps = p['traps']
    return True

def main():
    if not init():
        sys.exit()
    t = parse_trap()
    t = fix_format(t)
    t = ignore_trap(t)
    if t['status'] == 1:
        debug(t)
        logtofile(t)
        sys.exit()
    nsca_message = fix_nsca_message(t)
    # send trap to monitoring
    cmd = "echo -e \"%s\t%s\t%s\t%s\n\" | %s" % (t['sender_hostname'], "SNMP Traps", 2, t['uptime'] + " " + t['oid'] + " " + nsca_message, nsca_cmd)
    # used to ignore stderr
    fnull = open(os.devnull, 'w')
    if subprocess.call(cmd, shell = True, stdout = fnull, stderr = fnull):
        t = update_status(t, 3)
    else:
        t = update_status(t, 0)
    fnull.close()
    debug(t)
    logtofile(t)

if __name__ == "__main__":
    sys.exit(main());

# EOF
