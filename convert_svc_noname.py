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

def IP2Int( ip ):
  exp = 3
  intip = 0
  for quad in ip.split('.'):
    intip = intip + (int(quad) * (256 ** exp))
    exp = exp - 1
  return(intip)

def get_tg(ip):
  return  'traffic-group-dg-'+ str(IP2Int(ip) % 6)

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
keyvaluere = re.compile(r'^\s+([^\s]+)\s+(.+)$')
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

disabledreals = []
disabledvirts = []
disabledvrs = []

statusbyvr = {}
ipbyvr = {}

statusbyreal = {}
ipbyreal = {}
namebyreal = {}

healthbygroup = {}
contentbygroup = {}
realsbygroup = {}
namebygroup = {}


statusbyvirt = {}
ipbyvirt = {}
svcbyvirt = {}

groupbysvc = {}
namebysvc = {}
epipbysvc = {}
rportbysvc = {}

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
    linevalue = virt + '-' + svc
    continue

  m = realre.search(line)
  if m:
    real = m.group(1)
    linetype = 'real'
    linevalue = real
    continue

  m = groupre.search(line)
  if m:
    group = m.group(1)
    linetype = 'group'
    linevalue = group
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
    elif linetype == 'virt':
      statusbyvirt[linevalue] = state
      if state == 'dis':
        disabledvirts.append(linevalue)
    elif linetype == 'real':
      statusbyreal[linevalue] = state
      if state == 'dis':
        disabledreals.append(linevalue)
    elif linetype == 'vr':
      statusbyvr[linevalue] = state
      if state == 'dis':
        disabledvrs.append(linevalue)
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
    elif linetype == 'virt':
      if key == 'vip':
        ipbyvirt[linevalue] = value
    elif linetype == 'svc':
      if key == 'group':
        groupbysvc[linevalue] = value
      if key == 'hname':
        namebysvc[linevalue] = value.replace('"','')
      if key == 'epip':
        epipbysvc[linevalue] = value
      if key == 'rport':
        rportbysvc[linevalue] = value
    elif linetype == 'real':
      if key == 'rip':
        ipbyreal[linevalue] = value
      if key == 'name':
        namebyreal[linevalue] = value.replace('"','')
    elif linetype == 'group':
      if key == 'health':
        healthbygroup[linevalue] = value
      if key == 'content':
        contentbygroup[linevalue] = value
      if key == 'name':
        namebygroup[linevalue] = value.replace('"','')
      if key == 'add':
        if not realsbygroup.has_key(linevalue):
          realsbygroup[linevalue] = []
        realsbygroup[linevalue].append(value)
    elif linetype == 'vr':
      if key == 'addr':
        ipbyvr[linevalue] = value
    continue

  print >> sys.stderr, lineno, "ERROR, didn't match line : %s" % line

print 'loaded'
#for vlan in namebyvlan.keys():
#  print 'create vlan /PARTITION/' + namebyvlan[vlan].replace('\"','') + '_' + vlan + ' { interfaces add { 2.2 { tagged }} tag ' + vlan + ' }'
#for iface in keyvalue.keys():
#  print 'create self /PARTITION/iface-' + iface + ' { address ' + keyvalue[iface]['addr'] + '/' + keyvalue[iface]['mask'] + ' vlan ' + keyvalue[iface]['vlan'] + ' traffic-group local }'
print 'reals :'
for real in ipbyreal.keys():
  try:
    print 'real ' + real + ' : ' + namebyreal[real] + ' - ' + ipbyreal[real] + ' - ' + statusbyreal[real]
  except:
    print 'real ' + real + ' : NONAME - ' + ipbyreal[real] + ' - ' + statusbyreal[real]

f = open('group_noname_fix','w')
for group in realsbygroup.keys():
  try:
    print 'group ' + str(group) + ' : ' + namebygroup[group] + ' -  members : ' + str(realsbygroup[group]) + ' - check : ' + healthbygroup[group] + ' ' + contentbygroup[group]
  except:
    try:
      try:
        print 'group ' + str(group) + ' : ' + namebygroup[group] + ' -  members : ' + str(realsbygroup[group]) + ' - check : implicit TCP ' + contentbygroup[group]
      except:
        try:
          print 'group ' + str(group) + ' : ' + namebygroup[group] + ' -  members : ' + str(realsbygroup[group]) + ' - check : ' + healthbygroup[group] + ' NOCONTENT'
        except:
          print 'group ' + str(group) + ' : ' +  namebygroup[group] + ' -  members : ' + str(realsbygroup[group]) + ' - check : implicit TCP NOCONTENT'
    except:
      f.write('/c/slb/group ' + str(group) + '\n')
      try:
        print 'group ' + str(group) + ' : NONAME -  members : ' + str(realsbygroup[group]) + ' - check : implicit TCP ' + contentbygroup[group]
        f.write(' name ' + contentbygroup[group] + '\n')
      except:
        f.write(' name \n')
        try:
          print 'group ' + str(group) + ' : NONAME -  members : ' + str(realsbygroup[group]) + ' - check : ' + healthbygroup[group] + ' NOCONTENT'
        except:
          print 'group ' + str(group) + ' : NONAME -  members : ' + str(realsbygroup[group]) + ' - check : implicit TCP NOCONTENT'
f.close()

#print len(groupbysvc.keys())
#print len(namebysvc.keys())
#print len(epipbysvc.keys())
#print len(rportbysvc.keys())

are = re.compile(r'^([0-9]+)-([^\s]+)$')
for virtsvc in groupbysvc.keys():
  m = are.search(virtsvc)
  if m:
    virt = m.group(1)
    svc = m.group(2)
  try:
    print 'virt ' + virt + '(' + statusbyvirt[virt] + ') : ' + ipbyvirt[virt] + ':' + svc + ' - ' + namebysvc[virtsvc] + ' - group : ' + groupbysvc[virtsvc] + ' - epip : ' + epipbysvc[virtsvc]
  except:
    try:
      print 'virt ' + virt + '(' + statusbyvirt[virt] + ') : ' + ipbyvirt[virt] + ':' + svc + ' - ' + namebysvc[virtsvc] + ' - group : ' + groupbysvc[virtsvc] + ' - epip : NO'
    except:
      try:
        print 'virt ' + virt + '(' + statusbyvirt[virt] + ') : ' + ipbyvirt[virt] + ':' + svc + ' - NONAME - group : ' + groupbysvc[virtsvc] + ' - epip : ' + epipbysvc[virtsvc]
      except:  
        print 'virt ' + virt + '(' + statusbyvirt[virt] + ') : ' + ipbyvirt[virt] + ':' + svc + ' - NONAME - group : ' + groupbysvc[virtsvc] + ' - epip : NO'

print 'disabled reals : ' + str(disabledreals)
print 'disabled virts : ' + str(disabledvirts)
print 'disabled vrs   : ' + str(disabledvrs)

#f = open('nodes','w')
#for real in ipbyreal.keys():
#  try:
#    f.write('ltm node /legacy/' + namebyreal[real] + ' {\n')
#  except:
#    f.write('ltm node /legacy/NONAME {\n')
#  f.write('    address ' + ipbyreal[real] + '\n')
#  f.write('}\n')
#f.close()
#
#rport = None
#f = open('pools','w')
#for group in realsbygroup.keys():
#  try:
#    f.write('ltm pool /legacy/' + namebygroup[group] + '\n')
#  except:
#    f.write('ltm pool /legacy/NONAME\n')
#  f.write('    members {\n')
#  try:
#    virtsvc = [item[0] for item in groupbysvc.items() if item[1] == group ][0]
#  except:
#    print 'group ' + group + ' in no svc'
#  try:
#    port = rportbysvc[virtsvc]
#    rport = 'ok'
#  except:
#    m = are.search(virtsvc)
#    if m:
#      virt = m.group(1)
#      svc = m.group(2)
#  for member in realsbygroup[group]:
#    if rport == 'ok':
#      try:
#        f.write('        /legacy/' + namebyreal[member] + ':' + rport + ' {\n')
#      except:
#        f.write('        /legacy/NONAME:' + rport + ' {\n')
#    else:
#      try:
#        f.write('        /legacy/' + namebyreal[member] + ':' + svc + ' {\n')
#      except:
#        f.write('        /legacy/NONAME:' + svc + ' {\n')
#    f.write('            address ' + ipbyreal[member] + '\n')
#    f.write('        }\n')
#  f.write('    }\n')
#  f.write('    monitor /legacy/...\n')
#  f.write('    service-down-action drop\n')
#  f.write('}\n')
#  rport = None
#f.close()
#
#
