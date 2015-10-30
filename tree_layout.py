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
import collections


def get_hosts(filename):
    dc = {}
    file1 = open(filename, 'r')
    for line in file1.readlines():
        cell, hostname = line.split(',')
        service_name = format_name(hostname)
        if dc.get(cell) is None:
            dc[cell] = {}
        if dc[cell].get(service_name) is None:
            dc[cell][service_name] = []
        dc[cell][service_name].append(hostname.rstrip())
    return dc 

def format_name(name, no_format=False):
    # (Debug) print 'format_name - %s' % name
    if no_format:
        return name
    ip_expr = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_expr.match(name) is not None: 
        return 'Unknown_Service.%s' % name.replace('.', '-')
    service = re.compile("[0-9]").split(name)[0]
    return service

def create_json(dc):
    parent_json = {}
    parent_json["name"] = "sfx-aws"
    parent_json["children"] = []
    print dc.keys()
    for key, value_dict in dc.iteritems():
        child_json = {}
        child_json["name"] = key
        child_json["children"] = []
        print key
        print value_dict
        for k, v in value_dict.iteritems():
            v_dict = [{"name": v_item} for v_item in v]
            child_json["children"].append({"name": k, "children": v_dict})
        parent_json["children"].append(child_json)
    return parent_json

def main(filename):
    dc = get_hosts(filename)
    # print dc
    data = create_json(dc)
    with open('tree_layout.json', 'w') as outfile:
        json.dump(data, outfile)
        

if __name__ == '__main__':
    args = sys.argv
    if len(args) < 2:
        print 'Pass filename'
        exit(0)
    filename = args[1]
    main(filename)
