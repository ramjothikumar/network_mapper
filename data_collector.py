#!/usr/bin/env python

"""
This script captures the connections between multiple hosts and stores them in json.
Uses netstat to figure out the connections (udp & tcp)
"""

import json
from paramiko import SSHClient
import re
import sys
import time

cmd_get_conn = "netstat -anut | grep -v ':22' | awk {'print $5'} | grep -v '127.0.0.1' | grep -v '0.0.0.0' | grep -E -o '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sort | uniq"
cmd_get_bytes = "grep eth0: /proc/net/dev | awk {' print $2 \",\" $10 '}"

def get_hosts(filename):
    host_address = []
    file1 = open(filename, 'r')
    for line in file1.readlines():
        ip, hostname = line.split(',')
        host_address.append([ip, hostname.rstrip()])
    return host_address

def get_ip_fqdn_map(filename):
    ip_fqdn_map = {}
    file2 = open(filename, 'r')
    for line in file2.readlines():
        ip, hostname = line.split(',')
        ip_fqdn_map[ip] = hostname.rstrip()
    return ip_fqdn_map

def run_cmd_remote_host(ip, cmds):
    result = []
    client = SSHClient()
    client.load_system_host_keys()
    client.connect(ip, username="root")
    for cmd in cmds:
        stdin, stdout, stderr = client.exec_command(cmd)
        result.append([s.rstrip() for s in stdout.readlines()])
    return result

def get_total_bytes(tr_bytes):
    kb = 1024.0
    tbytes, rbytes = tr_bytes[0].split(',')
    return round(float(int(tbytes) + int(rbytes.rstrip()))/(kb*kb), 3)

def format_name(name):
    service = re.compile("[0-9]").split(name)[0]
    return '%s.%s' % (service, name)

def main(filename, filename_all=None):
    if filename_all is None:
        filename_all = filename
    data = []
    host_address = get_hosts(filename)
    # Tempotaty hack
    ip_fqdn_map = get_ip_fqdn_map(filename_all)
    for ip, hostname in host_address:
        print 'Gathering data for host - %s' % ip
        output_json = {}
        cmd_results = run_cmd_remote_host(ip, [cmd_get_conn, cmd_get_bytes])
        # Name field
        output_json['name'] = format_name(hostname)
        # Imports field
        output_json['imports'] = []
        remote_ips = cmd_results[0] 
        for r_ip in remote_ips:
            rem_name = ip_fqdn_map.get(r_ip) 
            if rem_name is not None:
                rem_name = format_name(rem_name)
            output_json['imports'].append(rem_name)
        # Total bytes
        tr_bytes = cmd_results[1] 
        output_json['size'] = get_total_bytes(tr_bytes)
        data.append(output_json)
    with open('output.json', 'w') as outfile:
        json.dump(data, outfile)
        

if __name__ == '__main__':
    args = sys.argv
    filename_all = None
    if len(args) < 2:
        print 'Pass filename'
        exit(0)
    filename = args[1]
    if len(args) > 2:
        filename_all = args[2]
    main(filename, filename_all=filename_all)
