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

cmd_get_conn = "netstat -anut | grep -v ':22' | awk {'print $5'} | grep -v '127.0.0.1' | grep -v '0.0.0.0' | grep -E -o '10.([0-9]{1,3}[\.]){2}[0-9]{1,3}' | sort | uniq"
cmd_get_bytes = "grep eth0: /proc/net/dev | awk {' print $2 \",\" $10 '}"

cmd_get_tcp_conn = "docker exec %s bash -c 'cat /proc/net/tcp*' | egrep -v 'rem|:0016' | awk {' print $3 '} | awk -F ':' {' print $1'} | sort | uniq"
cmd_get_udp_conn = "docker exec %s bash -c 'cat /proc/net/upp*' | egrep -v 'rem|:0016' | awk {' print $3 '} | awk -F ':' {' print $1'} | sort | uniq"

cmd_docker_check = "docker info | grep Containers"

allowable_classA_octets = ['10']
data = []
max_threads = 50
lock = threading.Lock()

def get_hosts(filename):
    host_address = []
    file1 = open(filename, 'r')
    for line in file1.readlines():
        ip, hostname = line.split(',')
        host_address.append([ip, hostname.rstrip()])
    return host_address

def convert_hex_to_ip(hex_ip):
    dec_ip = []
    if len(hex_ip) != 8:
        # (Debug) print "Value %s not a hex ip" % hex_ip
        return
    ip_list = [hex_ip[:2], hex_ip[2:4], hex_ip[4:6], hex_ip[6:8]]
    for i in reversed(ip_list):
        dec_ip.append(int('0x%s'% i, 16))
    return '.'.join([str(ip) for ip in dec_ip])

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
    try:
        client.connect(ip, username="root", timeout=3)
    # except paramiko.ssh_exception.AuthenticationException:
    except Exception:
        print 'ERROR: Authenticating to %s failed.' % ip
        return
    for cmd in cmds:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=3)
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

def get_docker_data(ip):
    raw_rem_ips = []
    rem_ips = []
    cmd = "docker ps | grep -v CONTAINER | awk {' print $1 '}"
    docker_ids = run_cmd_remote_host(ip, [cmd])[0]
    # (Debug) print 'docker_ids --- %s' % docker_ids
    for d_id in docker_ids:
        res = run_cmd_remote_host(ip, [cmd_get_tcp_conn % d_id])[0]
        if res:
            raw_rem_ips.extend(res)
        res = run_cmd_remote_host(ip, [cmd_get_udp_conn % d_id])[0]
        if res:
            raw_rem_ips.extend(res)
    # (Debug) print 'raw_rem_ips --- %s' % raw_rem_ips
    for rip in raw_rem_ips:
        rip = rip[-8:]
        if rip == '00000000' or rip == '0100007F':  continue
        ip = convert_hex_to_ip(rip)
        if ip is None:  continue
        for octet in allowable_classA_octets:
            if octet == ip.split('.')[0]:
                rem_ips.append(ip)
            else:
                continue
    return rem_ips

def worker(ip, hostname, ip_fqdn_map):
    print '--- Gathering data for host - %s' % ip
    # Getting data from host instance
    cmd_results = run_cmd_remote_host(ip, [cmd_get_conn, cmd_get_bytes, cmd_docker_check])
    if cmd_results is None:  return
    remote_ips = cmd_results[0] 
    # (Debug) print 'Remote IPs - %s' % remote_ips
    tr_bytes = get_total_bytes(cmd_results[1])
    # Getting data about the containers
    # (Debug) print 'docker info - %s' % cmd_results[2]
    if cmd_results[2] and 'Containers' in cmd_results[2][0]:
        docker_remote_ips = get_docker_data(ip)
        remote_ips.extend(docker_remote_ips)
    entry = create_entry(hostname, list(set(remote_ips)), tr_bytes, ip_fqdn_map=ip_fqdn_map)
    lock.acquire()
    data.append(entry)
    lock.release()
    return

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
    while len(threads) > 0:
        thrs = []
        for i in xrange(max_threads):
            try:
                thrs.append(threads.pop(0))
            except IndexError:
                break
        for t in thrs:
            t.start()
        for t in thrs:
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
