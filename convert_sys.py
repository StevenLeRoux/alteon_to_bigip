#!/usr/bin/env python
# _*_ coding: utf-8 _*_

import sys
import os.path
from os import chdir
import time
from time import localtime, strftime
import re



gents = time.time()
currentdir = os.getcwd()

if len(sys.argv) != 2:
  print >> sys.stderr, "Usage : python convert_sys.py my_alteon.conf"
  exit(1)

file = sys.argv[1]
if not os.path.isfile(file):
  print >> sys.stderr, "ERROR : unable to load : ",file
  exit(1)

ifre = re.compile(r'^/c/l3/if\s([0-9]+)$')
pipre = re.compile(r'^/c/slb/pip/add\s(.*)\s([0-9]+)$')
piptipre = re.compile(r'^/c/slb/pip/type\s(.*)$')
vlanre = re.compile(r'^/c/l2/vlan\s([0-9]+)$')
lacpre = re.compile(r'^/c/l2/lacp.*$')
stgre = re.compile(r'^/c/l2/stg.*$')
l3re = re.compile(r'^/c/l3/(vrrp/on|gw)\s*(.*)$')
vrre = re.compile(r'^/c/l3/vrrp/vr\s([0-9]+)$')
virtre = re.compile(r'^/c/slb/virt\s([0-9]+)$')
svcre = re.compile(r'^/c/slb/virt\s(.*)/service\s(.*)$')
groupre = re.compile(r'^/c/slb/group\s([0-9]+)$')
realre = re.compile(r'^/c/slb/real\s([0-9]+)$')
statere = re.compile(r'^\s+([^\s]+)$')
keyvaluere = re.compile(r'^\s+([^\s]+)\s(.*)$')
sysre = re.compile(r'^/c/sys.*$')
syncre = re.compile(r'^/c/slb/sync.*$')
advre = re.compile(r'^/c/slb(/adv)?$')
cfgre = re.compile(r'^/cfg/.*$')
portre = re.compile(r'^/c/(slb/)?port.*$')
commentre = re.compile(r'^/(\*.*)?$')
scriptre = re.compile(r'^script.*$')

ifs = []
vlans = []
vrs = []
virts = []
svcs = []
groups = []
reals = []
statusbyif = {}
ipverbyif = {}
addrbyif = {}
maskbyif = {}
broadbyif = {}
vlanbyif = {}
statusbyvlan = {}
namebyvlan = {}
learnbyvlan = {}
defbyvlan = {}
pipbyvlan = {}
keyvalue = {}

lineno = 0
linetype = '0'
linevalue = 0

conf = open(file,'r')

for line in conf:
  lineno += 1
#  line = line.strip()


  m = vrre.search(line)
  if m:
    vr = m.group(1)
    linetype = 'vr'
    linevalue = vr
    vrs.append(vr)
    continue

  m = virtre.search(line)
  if m:
    virt = m.group(1)
    linetype = 'virt'
    linevalue = virt
    virts.append(virt)
    continue

  m = svcre.search(line)
  if m:
    virt = m.group(1)
    svc = m.group(2)
    linetype = 'svc'
    linevalue = '0'
    continue

  m = realre.search(line)
  if m:
    real = m.group(1)
    linetype = 'real'
    linevalue = '0'
    continue

  m = groupre.search(line)
  if m:
    group = m.group(1)
    linetype = 'group'
    linevalue = '0'
    continue

  m = portre.search(line)
  if m:
    linetype = 'port'
    linevalue = '0'
    continue

  m = lacpre.search(line)
  if m:
    linetype = 'lacp'
    linevalue = '0'
    continue

  m = commentre.search(line)
  if m:
    linetype = 'comment'
    linevalue = '0'
    continue

  m = scriptre.search(line)
  if m:
    linetype = 'script'
    linevalue = '0'
    continue

  m = stgre.search(line)
  if m:
    linetype = 'stg'
    linevalue = '0'
    continue

  m = l3re.search(line)
  if m:
    linetype = 'l3'
    linevalue = '0'
    continue

  m = sysre.search(line)
  if m:
    linetype = 'sys'
    linevalue = '0'
    continue

  m = syncre.search(line)
  if m:
    linetype = 'sys'
    linevalue = '0'
    continue

  m = cfgre.search(line)
  if m:
    linetype = 'sys'
    linevalue = '0'
    continue

  m = advre.search(line)
  if m:
    linetype = 'sys'
    linevalue = '0'
    continue


  m = piptipre.search(line)
  if m:
    linetype = 'piptip'
    linevalue = '0'
    continue

  m = pipre.search(line)
  if m:
    pipip = m.group(1)
    pipvlan = m.group(2)
    linetype = 'pip'
    linevalue = '0'

    if not pipbyvlan.has_key(pipvlan):
      pipbyvlan[pipvlan] = pipip
    continue

  m = ifre.search(line)
  if m:
    ifid = m.group(1)
    linetype = 'if'
    linevalue = ifid

    ifs.append(ifid)
    if not keyvalue.has_key(linevalue):
      keyvalue[linevalue] = {}
    continue

  m = vlanre.search(line)
  if m:
    vlanid = m.group(1)
    linetype = 'vlan'
    linevalue = vlanid

    vlans.append(vlanid)
    continue

  m = statere.search(line)
  if m:
    state = m.group(1)
    if linetype in ('if','vlan'):
      if linetype == 'if':
        statusbyif[linevalue] = state
      else:
        statusbyvlan[linevalue] = state
    continue

  m = keyvaluere.search(line)
  if m:
    key = m.group(1)
    value = m.group(2)
    if linetype in ('if','vlan'):
      if linetype == 'if':
        if not keyvalue[linevalue].has_key(key):
          keyvalue[linevalue][key] = {}
        keyvalue[linevalue][key] = value
      else:
        if key == 'name':
          namebyvlan[vlanid] = value
        if key == 'learn':
          learnbyvlan[vlanid] = value
        if key == 'def':
          defbyvlan[vlanid] = value
    continue

  print >> sys.stderr, lineno, "ERROR, didn't match line : %s" % line

print 'loaded'
for vlan in namebyvlan.keys():
  print 'create vlan /PARTITION/' + namebyvlan[vlan].replace('\"','') + '_' + vlan + ' { interfaces add { 2.2 { tagged }} tag ' + vlan + ' }'
for iface in keyvalue.keys():
  print 'create self /PARTITION/iface-' + iface + ' { address ' + keyvalue[iface]['addr'] + '/' + keyvalue[iface]['mask'] + ' vlan ' + keyvalue[iface]['vlan'] + ' traffic-group local }'
