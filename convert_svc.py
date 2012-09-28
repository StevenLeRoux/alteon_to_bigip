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

def get_vlan(ip):
  intip = IP2Int(ip)
  if IP2Int(ip) in range (177872128,177872383) or IP2Int(ip) in range (177899520,177900543):
    return 'vlan129'
  elif IP2Int(ip) in range (177268736,177269759):
    return 'vlan130'
  else:
    return 'unknown'

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

for virt in  sorted(ipbyvirt.keys()):
  print ipbyvirt[virt] + ':' + virt
exit()

print 'loaded'

are = re.compile(r'^([0-9]+)-([^\s]+)$')
bre = re.compile(r'^[0-9]+[^\s]*$')

f = open('nodes','w')
for real in ipbyreal.keys():
  try:
    n = bre.search(namebyreal[real])
    if n:
      f.write('ltm node /legacy/Node_' + namebyreal[real] + ' {\n')
    else:
      f.write('ltm node /legacy/' + namebyreal[real] + ' {\n')
  except:
    f.write('ltm node /legacy/NONAME {\n')
  f.write('    address ' + ipbyreal[real] + '\n')
  f.write('}\n')
f.close()

rport = None
f = open('pools','w')
g = open('monitors','w')
for group in realsbygroup.keys():
  try:
    n = bre.search(namebygroup[group])
    if n:
      f.write('ltm pool /legacy/Pool_' + namebygroup[group].replace('-lb','') + ' {\n')
    else:
      f.write('ltm pool /legacy/' + namebygroup[group].replace('-lb','') + ' {\n')
  except:
    f.write('ltm pool /legacy/NONAME\n')
  f.write('    members {\n')
  try:
    virtsvc = [item[0] for item in groupbysvc.items() if item[1] == group ][0]
  except:
    print 'group ' + group + ' in no svc'
  try:
    port = rportbysvc[virtsvc]
    rport = 'ok'
  except:
    m = are.search(virtsvc)
    if m:
      virt = m.group(1)
      svc = m.group(2)
  for member in realsbygroup[group]:
    if rport == 'ok':
      try:
        n = bre.search(namebyreal[member])
        if n:
          f.write('        /legacy/Node_' + namebyreal[member] + ':' + rportbysvc[virtsvc] + ' {\n')
        else:
          f.write('        /legacy/' + namebyreal[member] + ':' + rportbysvc[virtsvc] + ' {\n')
      except:
        f.write('        /legacy/NONAME:' + rport + ' {\n')
    else:
      try:
        n = bre.search(namebyreal[member])
        if n:
          f.write('        /legacy/Node_' + namebyreal[member] + ':' + svc + ' {\n')
        else:
          f.write('        /legacy/' + namebyreal[member] + ':' + svc + ' {\n')
      except:
        f.write('        /legacy/NONAME:' + svc + ' {\n')
    f.write('            address ' + ipbyreal[member] + '\n')
    f.write('        }\n')
  f.write('    }\n')
  try:
    if contentbygroup[group] == '"/apcheck"':
      monitor = '/Common/webhub'
    else:
      if not healthbygroup.has_key(group):
        monitor = '/Common/tcp'
      else:
        n = bre.search(namebygroup[group])
        if n:
          monitor = '/legacy/Monitor_' + namebygroup[group].replace('-lb','')
        else:
          monitor = '/legacy/' + namebygroup[group].replace('-lb','')
        g.write('ltm monitor http ' + monitor + ' {\n')
        g.write('    defaults-from /Common/http\n')
        g.write('    destination *:*\n')
        g.write('    interval 30\n')
        g.write('    recv "200 OK"\n')
        g.write('    send "GET ' + contentbygroup[group].replace('"','') + '\\r\\n"\n')
        g.write('    time-until-up 0\n')
        g.write('    timeout 10\n')
        g.write('}\n')
  except:
    try:
      if healthbygroup[group] in ['tcp','http','https','udp']:
        monitor = '/Common/' + healthbygroup[group]
    except:
      monitor = '/Common/tcp'
  f.write('    monitor ' + monitor.replace('-lb','')  +'\n')
  f.write('    service-down-action reselect\n')
  f.write('}\n')
  rport = None
f.close()
g.close()

f = open('virt_adresses','w')
g = open('virt_servers','w')
h = open('legacy.ref','w')
for virtsvc in groupbysvc.keys():
  m = are.search(virtsvc)
  if m:
    virt = m.group(1)
    svc = m.group(2)
  f.write('ltm virtual-address /legacy/' + ipbyvirt[virt] + ' {\n')
  f.write('    address ' + ipbyvirt[virt] + '\n')
  f.write('    enabled no\n')
  f.write('    mask 255.255.255.255\n')
  f.write('    traffic-group /Common/' + get_tg(ipbyvirt[virt]) + '\n')
  f.write('}\n')
  n = bre.search(namebysvc[virtsvc])
  if n:
    g.write('ltm virtual /legacy/VS_' + namebysvc[virtsvc].replace('-lb','')  + ' {\n')
    h.write('vs    ' + ipbyvirt[virt] + ':' + svc + ' VS_' + namebysvc[virtsvc].replace('-lb','')  + '  ENABLED\n')
  else:
    g.write('ltm virtual /legacy/' + namebysvc[virtsvc].replace('-lb','')  + ' {\n')
    h.write('vs    ' + ipbyvirt[virt] + ':' + svc + ' ' + namebysvc[virtsvc].replace('-lb','')  + '  ENABLED\n')
  g.write('    destination /legacy/' + ipbyvirt[virt] + ':' + svc +'\n')
  g.write('    ip-protocol tcp\n')
  g.write('    mask 255.255.255.255\n')
  n = bre.search(namebygroup[groupbysvc[virtsvc]])
  if n:
    g.write('    pool /legacy/Pool_' + namebygroup[groupbysvc[virtsvc]].replace('-lb','') + '\n')
  else:
    g.write('    pool /legacy/' + namebygroup[groupbysvc[virtsvc]].replace('-lb','') + '\n')
  g.write('    profiles {\n')
  try:
    if healthbygroup[groupbysvc[virtsvc]] in ['http']:
      g.write('        /Common/http { }\n')
      g.write('        /Common/httpcompression { }\n')
      g.write('        /Common/oneconnect { }\n')
      g.write('        /Common/tcp { }\n')
    elif healthbygroup[groupbysvc[virtsvc]] in ['udp']:
      g.write('        /Common/udp { }\n')
  except:
      g.write('        /Common/oneconnect { }\n')
      g.write('        /Common/tcp { }\n')
  g.write('    }\n')
  g.write('    snat automap\n')
  g.write('    vlans {\n')
  g.write('        /legacy/' + get_vlan(ipbyvirt[virt]) + '\n')
  g.write('    }\n')
  g.write('    vlans-enabled\n')
  g.write('}\n')
f.close()
g.close()
h.close()
