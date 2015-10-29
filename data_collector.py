#!/usr/bin/env python

"""
This script captures the connections between multiple hosts and stores them in json.
Uses netstat to figure out the connections (udp & tcp)
"""

import json
import paramiko
import re
import sys
import threading
import time

# cmd_get_conn = "netstat -anut | grep -v ':22' | awk {'print $5'} | grep -v '127.0.0.1' | grep -v '0.0.0.0' | grep -E -o '([0-9]{1,3}[\.]){3}[0-9]{1,3}' | sort | uniq"
cmd_get_conn = "netstat -anut | grep -v ':22' | awk {'print $5'} | grep -v '127.0.0.1' | grep -v '0.0.0.0' | grep -E -o '10.([0-9]{1,3}[\.]){2}[0-9]{1,3}' | sort | uniq"
cmd_get_bytes = "grep eth0: /proc/net/dev | awk {' print $2 \",\" $10 '}"
data = []
lock = threading.Lock()

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
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username="root")
    for cmd in cmds:
        stdin, stdout, stderr = client.exec_command(cmd)
        result.append([s.rstrip() for s in stdout.readlines()])
    return result

def get_total_bytes(tr_bytes):
    kb = 1024.0
    tbytes, rbytes = tr_bytes[0].split(',')
    return round(float(int(tbytes) + int(rbytes.rstrip()))/(kb*kb), 3)

def format_name(name, no_format=False):
    # (Debug) print 'format_name - %s' % name
    if no_format:
        return name
    ip_expr = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_expr.match(name) is not None: 
        return 'Unknown_Service.%s' % name.replace('.', '-')
    service = re.compile("[0-9]").split(name)[0]
    return '%s.%s' % (service, name)

def sanitize_data(data):
    dnames = [d['name'] for d in data]
    new_data = []
    for d in data:
        for rem_name in d['imports']:
            if rem_name not in dnames and rem_name not in [i['name'] for i in new_data]:
                print 'Remote IP Name %s not present in name. Adding it' % rem_name
                new_data.append(create_entry(rem_name, [], 0, no_format=True)) 
    data.extend(new_data)
    return

def create_entry(name, remote_ips, size, ip_fqdn_map={}, no_format=False):
    output_json = {}
    # Name field
    output_json['name'] = format_name(name, no_format=no_format)
    # Imports field
    output_json['imports'] = []
    for r_ip in remote_ips:
        rem_name = ip_fqdn_map.get(r_ip, r_ip)
        output_json['imports'].append(format_name(rem_name, no_format=no_format))
    # (Debug) print 'Remote hosts in json - %s' % output_json['imports']
    # Total bytes
    output_json['size'] = size
    return output_json

def worker(ip, hostname, ip_fqdn_map):
    print '--- Gathering data for host - %s' % ip
    cmd_results = run_cmd_remote_host(ip, [cmd_get_conn, cmd_get_bytes])
    remote_ips = cmd_results[0] 
    # (Debug) print 'Remote IPs - %s' % remote_ips
    tr_bytes = get_total_bytes(cmd_results[1])
    entry = create_entry(hostname, remote_ips, tr_bytes, ip_fqdn_map=ip_fqdn_map)
    lock.acquire()
    data.append(entry)
    lock.release()

def main(filename, filename_all=None):
    if filename_all is None:
        filename_all = filename
    threads = []
    host_address = get_hosts(filename)
    ip_fqdn_map = get_ip_fqdn_map(filename_all)
    for ip, hostname in host_address:
        # (Debug) worker(ip, hostname, ip_fqdn_map)
        t = threading.Thread(target=worker, args=(ip, hostname, ip_fqdn_map))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sanitize_data(data)
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
