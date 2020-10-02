# -*- coding: utf-8 -*-
"""
::::::::::::::::::::::::  Critical Infrastructure Cyberspace Analysis Tool (CICAT)  :::::::::::::::::::::::::::::::::::::::

                                            NOTICE
                                            
The contents of this material reflect the views of the author and/or the Director of the Center for Advanced Aviation 
System Development (CAASD), and do not necessarily reflect the views of the Federal Aviation Administration (FAA) 
or the Department of Transportation (DOT). Neither the FAA nor the DOT makes any warranty or guarantee, or promise, 
expressed or implied, concerning the content or accuracy of the views expressed herein. 

This is the copyright work of The MITRE Corporation and was produced for the U.S. Government under Contract Number 
DTFAWA-10-C-00080 and is subject to Federal Aviation Administration Acquisition Management System Clause 3.5-13, 
Rights in Data-General, Alt. III and Alt. IV (Oct. 1996). No other use other than that granted to the U.S. Government, 
or to those acting on behalf of the U.S. Government, under that Clause is authorized without the express written permission 
of The MITRE Corporation. For further information, please contact The MITRE Corporation, Contract Office, 7515 Colshire Drive, 
McLean, VA 22102 (703) 983-6000. ©2020 The MITRE Corporation. 

The Government retains a nonexclusive, royalty-free right to publish or reproduce this document, or to allow others to do so, for 
“Government Purposes Only.”                                           
                                            
(c) 2020 The MITRE Corporation. All Rights Reserved.

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
zoneCrawlr.py - Interactive utility to evaluate infrastructure and topology
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import sys

from loaddata import LOAD_DATA, m_file_TESTBED_MODEL, m_file_TESTBED_SCNRO  
from topology import INIT_TOPOLOGY, m_topology, m_zoneCIs

#assumes zone IDs prefixed with 1 digit security level, returns [level, zoneID]
def zoneSplit (zone):
    return [int(zone[0], zone[1:])]
        
def findZone (zone):
    level = int(zone[0])
    znx = zone[1:]
    for j in m_topology[level]:
        if znx == j[0][1]:
            return j    

def findZonebyIP(dataset, ipaddr ):
    cmp = findTargetComponentIP(dataset, ipaddr )
    if not(cmp):
        print ('Could not find compoent', ipaddr)
        return

    sys = cmp.getSystem()
    if sys:
        return str(sys.getLevel())+sys.getZone()

def findTargetSystem(dataset, sysname ):
    for sysm in dataset['SYSTEM']:
        if (sysm.getName() == sysname):
           return sysm
       
def findFunction (dataset, fname ):
    for fx in dataset['FUNCTION']:
        if fx.getName() == fname:
            return fx
    
def findTargetComponentIP(dataset, ipaddr ):
    for cmp in dataset['COMPONENT']: 
        if (cmp.getIPAddress()== ipaddr):
            return cmp
        
def getSystemIPList(dataset, sysname ):
    ret = []
    for cmp in dataset['COMPONENT']: 
        if (cmp.getSysName()== sysname):
            ret.append(cmp.getIPAddress()  )
    return ret

# returns IPs in a zone
def whosLocalZone (zone, bflatzone):
    ret = []
    zonedata = findZone(zone )
    if not(zonedata):
        print('no zonedata for', zone)
        return None
    for k in zonedata[1:]:
        if bflatzone:
           for q in k[1]:
                 ret.append(q)
        else:
            ret.append(k[1])
    return ret
    
#returns IPs local to IP
def whosLocalIP (dataset, ipaddr, bflatzone ): 
    zone = findZonebyIP(dataset, ipaddr  ) 
    return whosLocalZone (zone, bflatzone )

# returns IPs in zones connected through controlled interface
def whosRemoteIP(dataset, ipaddr ):
    ret = []
    zone = findZonebyIP(dataset, ipaddr  ) 

    if m_zoneCIs[zone]:
        for ci in m_zoneCIs[zone]:
            print ('CI:', ci.getCIName(), 'Type:', ci.getCIType() )
            zonedata = ci.getDstZoneDetails()
            for j in zonedata[1:]:
              iplist = j[1]
              for ip in iplist:
                 ret.append (ip )
    return ret
        
def getSurfaceList (dataset, ip):
    cmp = findTargetComponentIP(dataset, ip)
    return cmp.getEntrypointList()   

# recursive path traversal algorithms
def find_path(graph, start, end, path=[]):
        path = path + [start]
        if start == end:
            return path

        if not (start in graph):
            return None
        for node in graph[start]:
            if node not in path:
                newpath = find_path(graph, node, end, path)
                if newpath: return newpath
        return None
    
def find_all_paths(graph, start, end, path=[]):
        path = path + [start]
        if start == end:
            return [path]
        if not (start in graph):
            return []
        paths = []
        for node in graph[start]:
            if node not in path:
                newpaths = find_all_paths(graph, node, end, path)
                for newpath in newpaths:
                    paths.append(newpath)
        return paths

def find_shortest_path(graph, start, end, path=[]):
        path = path + [start]
        if start == end:
            return path

        if not (start in graph):
            return None
        shortest = None
        for node in graph[start]:
            if node not in path:
                newpath = find_shortest_path(graph, node, end, path)
                if newpath:
                    if not shortest or len(newpath) < len(shortest):
                        shortest = newpath
        return shortest

# looks for ip2 in local zone and remote zone(s) via source zone CIs (1 hop)    
def bIsPATH (dataset, graph, ip1, ip2):
    if not(graph) or not(ip1) or not(ip2):
        return False

    if (ip1 == ip2):
        return True

    srczone = findZonebyIP(dataset, ip1 )    
    dstzone = findZonebyIP(dataset, ip2 )

    path = find_path (graph, srczone, dstzone)
    if path:
        return True    
    return False

def getZonepath (graph, zone1, zone2, bShortPath, trace):
    
    ret = []
    if trace: 
       if bShortPath:
          print ('\nFinding shortest path from', zone1, 'to', zone2)
       else:
          print ('\nFinding path from', zone1, 'to', zone2)
             
    if bShortPath:
        ret = find_shortest_path(graph, zone1, zone2)
    else:
        plist = find_all_paths (graph, zone1, zone2)
        if trace:
            print (str(len(plist)), 'paths found')
        if len(plist) < 1:
            return None
        ret = plist
       
    if trace:
        print ('path', ret)

    return ret
 
def isLast(listx, item):
    llen = len(listx)
    cur = listx.index(item) +1
    if cur >= llen:
        return True
    return False

def getTargetList(dataset, zone, bBest):
    ret = []
    iplist = whosLocalZone (zone, True)
    
    if iplist:
        maximpact = 0
        for j in iplist:
            cmp = findTargetComponentIP(dataset, j)
            val = cmp.getImpactScore()
            if val > maximpact:
                maximpact = val
     
        for j in iplist:
            cmp = findTargetComponentIP(dataset, j )
            val = cmp.getImpactScore()
            if not(bBest):
               ret.append ([j, cmp.getSysName(), val])
            elif val == maximpact:
                ret.append ([j, cmp.getSysName(), val])

    return ret


def findTarget(dataset, tgtobj ):
    ttype = tgtobj.getType()
    tname = tgtobj.getName()    
    if ttype.lower() == 'COMPONENT'.lower():
        for j in dataset['COMPONENT']:
            if j.getName().lower() == tname.lower():
                return j
    elif ttype.lower() == 'SYSTEM'.lower():
        for j in dataset['SYSTEM']:
            if j.getName().lower() == tname.lower():
                return j
    elif ttype.lower() == 'FUNCTION'.lower():
        for j in dataset['FUNCTION']:
            if j.getName().lower() == tname.lower():
                return j            
    else:
        print ('Could not find target object:', ttype, tname) 


# returns the list of functions that sysnname supports
def get2ndOrderEffects(dataset, sysname ):
    ret = []
    temp = set()
    sys = findTargetSystem(dataset, sysname )
    if sys:
       flist = sys.getFunctionList()
       if flist:
          for f in flist:
             fname = f.getName()
             temp.add(fname )   
             
    for j in temp:
        ret.append (j)
    return ret

#returns list of capabiities that sysname supports
def get3rdOrderEffects(dataset, sysname ):
    ret = []
    temp = set()
    flist = get2ndOrderEffects(dataset, sysname )
    if flist:
        for f in flist:
          fx = findFunction(dataset, f)
          if fx:
             capname = fx.getCapability()
             temp.add(capname)
             
    for j in temp:
        ret.append(j)

    return ret
            

def targetToDisruptSystem (dataset, sysname, bMaxImpact):
    fullist = []
    topscore = 0
    for j in dataset['SYSTEM']:
        if j.getName() == sysname:
            clist = j.getComponentList()
            if not(clist):
                return fullist            
            for c in clist:
               if c.getImpactScore() > topscore:
                  topscore = c.getImpactScore()
               fullist.append ([c.getIPAddress(), c.getImpactScore()] )
            break
    
    if not(bMaxImpact):
        return fullist
   
    retlist = []
    for p2 in fullist:
        if int(p2[1]) == topscore:
            retlist.append(p2)
            
    return retlist

def targetToDisruptFunction (dataset, fxname, bMaxImpact, bFlatlist):
    fullist = []
    for j in dataset['FUNCTION']:
        if j.getName() == fxname:
            slist = j.getSystemList()
            if not(slist):
                return fullist            
            for s in slist:
               clist = targetToDisruptSystem (dataset, s.getName(), bMaxImpact )
               if bFlatlist:
                  for c in clist:
                      fullist.append (c)
               else:                  
                  fullist.append ([s.getName(), clist] )
            break 
            
    return fullist

def targetToDisruptCapability (dataset, capname, bMaxImpact, bFlatlist):
    fullist = []
    for j in dataset['CAPABILITY']:
        if j.getName() == capname:
            flist = j.getFunctionList()
            if not(flist):
                return fullist            
            for f in flist:
               clist = targetToDisruptFunction (dataset, f.getName(), bMaxImpact, bFlatlist )
               if bFlatlist:
                   for c in clist:
                     fullist.append ( c )
               else:
                   fullist.append ([f.getName(), clist])
            break 
            
    return fullist  

def getSurfacesByAccess(dataset, zone, access):
    ret = []
    iplist = whosLocalZone (zone, True)
    if iplist:
        for j in iplist:
            cmp = findTargetComponentIP(dataset, j )
            eplist = cmp.getSurfaceList()
            if eplist:
                for e in eplist:
                    if (e.getAccess().lower() == access.lower()):
                        ret.append ([j, cmp.getSysName(), e.getSurfaceType(), e.getAccess()] )
    return ret

def getSurfacesByType(dataset, zone, typex ):
    ret = []
    iplist = whosLocalZone (zone, True)
    if iplist:
        for j in iplist:
            cmp = findTargetComponentIP(dataset, j )
            eplist = cmp.getSurfaceList()
            if eplist:
                for e in eplist:
                    if (e.getSurfaceType().lower() == typex.lower()):
                        ret.append ([j, cmp.getSysName(), e.getSurfaceType(), e.getAccess() ] )
    return ret

def getSurfacesByZone(dataset, zone):
    ret = []
    iplist = whosLocalZone (zone, True)
    if iplist:
        for j in iplist:
            cmp = findTargetComponentIP(dataset, j )
            eplist = cmp.getSurfaceList()
            if eplist:
                for e in eplist:
                    ret.append ([j, cmp.getSysName(), e.getSurfaceType(), e.getAccess()] )
    return ret

def lastStep(path, step):
    if step == path[len(path)-1]:
        return True
    return False

# returns IP of component with highest accessibility and/or susceptibility
def selectNextTarget(dataset, tlist):

    component_tuples = []
    sorted_tuples = []

    for t in tlist:
        cmp = findTargetComponentIP (dataset, t)
        acc = cmp.getAccessibility()
        sus = cmp.getSusceptibility()
        component_tuples.append([acc, sus, acc*sus, t])

    sorted_tuples = sorted(component_tuples, key=lambda component: component[2], reverse=True  )
    if component_tuples == sorted_tuples:
        sorted_tuples = sorted(component_tuples, key=lambda component: component[1], reverse=True  )
        if component_tuples == sorted_tuples:
            sorted_tuples = sorted(component_tuples, key=lambda component: component[0], reverse=True  )

    return sorted_tuples[0][3]


def traversePath(dataset, path, startIP, targetIP, surfaceType, platType, bAddCIs, trace ):

    ret = [startIP]    
    if path:
      for step in path:   
        bLast = False
        iplist = whosLocalZone(step, True )
        if lastStep(path, step):
            bLast = True            
            if trace:
                print ('Last step in', path, 'is', step)
            iplist = [targetIP]
        
        if not(iplist):
            print ('WARNING! No iplist for', step)
            return
        
        bAnyPlat = False
        if platType.lower().startswith('any'):
            bAnyPlat = True
            
        bAnySurf = False
        if surfaceType.lower().startswith('any'):
           bAnySurf = True
        
        fltlist = []
        for ip in iplist:
            cmp = findTargetComponentIP(dataset, ip )
            if bLast:
                if trace:
                    print ('Last IP:', ip )
                fltlist.append(ip) 
                
            else:
             
                if not(bAnyPlat):
                    if cmp.getPlatform() != platType:
                        continue
                    
                if not(bAnySurf):
                    slist = cmp.getSurfaceList()
                    found = False
                    for j in slist:
                        if j.getSurfaceType() == surfaceType:
                            found = True
                            break
                    
                    if not(found):
                        continue
                     
                fltlist.append (ip)
        
        if trace:
           print ('Zone', step, 'Surface:', surfaceType, 'Platform:', platType, 'IPs:', fltlist )

        if not(fltlist):
            if trace:
                print ('No IPs match requirements: surface:', surfaceType, 'platform:', platType )
            return

        ret.append(selectNextTarget(dataset, fltlist ) ) 
            
        if bAddCIs:
            if isLast(path, step):
                return ret

            cilist = m_zoneCIs[step]
            if (len(cilist) == 1):
               ret.append(cilist[0].getCIName())
            else:
               nxtstep = path[path.index(step)+1]
               for ci in cilist:
                  if ci.getDstZoneName() == nxtstep:
                     ret.append(ci.getCIName())
                     break             
    return ret      
    
def substring_after(s, delim):
    return s.split(delim)[1]

def show_zonemap(zmap):
   print ('Zone Map:', zmap)
   print('\n')

def show_ip(dataset, cArray, bshoVs ):
    
   if (len(cArray) < 2):
      print ('shoip ipaddress' )
      return    
  
   ip = cArray[1]
   cmp = findTargetComponentIP(dataset, ip )
   print ('\nIP:', ip, 'System:', cmp.getSysName(), 'Zone:', findZonebyIP(dataset, ip ))
   print ('Vendor:', cmp.getVendor(), 'Type:', cmp.getType(), cmp.getDesc(), 
          'Platform:', cmp.getPlatform() )
   
   eplist = cmp.getSurfaceList ()
   if eplist:
        print ('Surfaces:')
        for e in eplist:
            e.PP() 
            
   if bshoVs:
      vlist = cmp.getVulnerabilityList()
      if vlist:
         print ('Vulnerabilities:')
         for v in vlist:
             v.PP()

def show_sys(dataset, cArray ):
    if (len(cArray) < 2):
        print ('shosys system_name')
        return
    
    strArg = ''
    slist = cArray[1:]
    for s in slist:
        strArg = strArg + ' ' + s
    
    sysm = findTargetSystem(dataset, strArg.lstrip() )
    if sysm:
       sysm.PP()
    else:
       print (strArg.lstrip(),'not found.')
    

def do_zonepath(cArray, zmap, trace):
        if (len(cArray) < 4):
            print ('path <srczn> <dstzn> all|shortest' )
            return
            
        srczn = cArray[1]
        dstzn = cArray[2]
        bshortest = True
        if cArray[3].lower() == 'all':
            bshortest = False

        zpaths = getZonepath (zmap, srczn, dstzn, bshortest, False)
        if not(zpaths):
            if trace:
               print('No paths found from', srczn, 'to', dstzn+'.')
            return
            
        if trace:
           if not(bshortest):
               print ('There are', str(len(zpaths)), 'paths from', srczn, 'to', dstzn+':')
               print (zpaths)
           else:
              print ('Shortest path from', srczn, 'to', dstzn+':')
              print (zpaths)
           
        return zpaths

def do_zonetargets(dataset, cArray, trace):
        if (len(cArray) < 3):
            print ('targets <zone> all|best' )
            return
            
        srczn = cArray[1]
        bBest = False
        tmode = cArray[2].lower()
        if tmode.lower() == 'best':
            bBest = True
 
        tlist = getTargetList(dataset, srczn, bBest )
        if not(tlist):
            print ('No targets in zone', srczn+'.')
            return
        
        if trace:
           print (str(len(tlist)), 'targets in zone', srczn+':')
           for t in tlist:
               print('IP:',t[0], 'System:', t[1], 'Score:', t[2])            

        return tlist

def do_zonends (dataset, cArray, trace):
        if (len(cArray) < 3):
          print ('surfaces <zone> all|type=<value>|access=<value> [Use doublequotes for strings]')
          return
            
        srczn = cArray[1]
        cmdstr = cArray[2]
        alist = []
        if cmdstr.lower().count('type') > 0:
            paramx = substring_after (cmdstr, '=')
            alist = getSurfacesByType(dataset, srczn, paramx)
        elif cmdstr.lower().count('access') > 0:
            paramx = substring_after (cmdstr, '=')
            alist = getSurfacesByAccess(dataset, srczn, paramx)
        else:
            alist = getSurfacesByZone(dataset, srczn)

        if not(alist):
            if trace:
               print('No surfaces found in', srczn+'.')
            return

        if trace:
           print (str(len(alist)), 'surfaces in zone', srczn+':')
           for a in alist:
               print ('IP:', a[0], 'System:', a[1], 'Type:', a[2], 'Access:', a[3])
            
        return alist

def do_disruptSYS (dataset, cArray, trace):
 
    if (len(cArray) < 3):
       print ('disys flat=true|false system_name' )
       return
           
    bFlat = False
    fstop = cArray[1]
    if (fstop.split('=')[1].lower() == 'true'):
        bFlat = True
        
    strArg = ''
    flist = cArray[2:]
    for w in flist:
        strArg = strArg + ' ' + w
      
    listx = targetToDisruptSystem(dataset, strArg.lstrip(), bFlat )
    if trace:
       if bFlat:
           print ('\n'+str(len(listx)), 'flatlist target IPs in', strArg.lstrip()+':')
       else:
           print ('\n'+str(len(listx)), 'target IPs in', strArg.lstrip()+':')
        
       for j in listx:
           print (j)

    return listx

def do_disruptFX (dataset, cArray, trace):
 
    if (len(cArray) < 4):
       print ('disfx flat=true|false list=full|top function_name' )
       return
           
    bFlat = False
    fstop = cArray[1]
    if (fstop.split('=')[1].lower() == 'true'):
        bFlat = True

    bTop = False
    lstop = cArray[2]
    if (lstop.split('=')[1].lower() == 'top'):
        bTop = True           

    strArg = ''
    flist = cArray[3:]
    for w in flist:
        strArg = strArg + ' ' + w
      
    listx = targetToDisruptFunction(dataset, strArg.lstrip(), bTop, bFlat )
    if trace:
       if bFlat:
           print ('\n'+str(len(listx)), 'target IPs in', strArg.lstrip()+':')
       else:
           print ('\n'+str(len(listx)), 'targets in', strArg.lstrip()+':')
        
       for j in listx:
           print (j)

    return listx

def do_disruptCAP (dataset, cArray, trace):
 
    if (len(cArray) < 4):
       print ('discap flat=true|false list=full|top capability_name' )
       return
           
    bFlat = False
    fstop = cArray[1]
    if (fstop.split('=')[1].lower() == 'true'):
        bFlat = True

    bTop = False
    lstop = cArray[2]
    if (lstop.split('=')[1].lower() == 'top'):
        bTop = True           

    strArg = ''
    flist = cArray[3:]
    for w in flist:
        strArg = strArg + ' ' + w
      
    listx = targetToDisruptCapability(dataset, strArg.lstrip(), bTop, bFlat )
    if trace:
       if bFlat:
           print ('\n'+str(len(listx)), 'flatlist targets in', strArg.lstrip()+':')
       else:
           print ('\n'+str(len(listx)), 'targets in', strArg.lstrip()+':')
        
       for j in listx:
           print (j)

    return listx

def do_traverse(dataset, zonemap, cArray, trace):

    if (len(cArray) < 5):
       print ('attack <startIP> <targetIP> <surface> <platform>' )
       return
   
    startIP = cArray[1]
    targetIP = cArray[2]
    surface = cArray[3]
    platform = cArray[4]
    

    startzn = findZonebyIP(dataset, startIP )
    tgtzone = findZonebyIP(dataset, targetIP )
        
    path = getZonepath (zonemap, startzn, tgtzone, True, False )   
    iplist = traversePath(dataset, path, startIP, targetIP, surface, platform, False, False )
    
    if not(iplist):
        if trace:
           print ('No path found.')
        return

    if trace:
       print('\nTHREAT VECTOR WAYPOINTS:')
       for ip in iplist:       
           show_ip(dataset, [' ', ip], trace )
        
    return iplist
    

# Helper function for reading options from command line
def optionReader(params, flag):
    idx = params.index(flag)
    if len(params) > idx + 1 and '-' not in params[idx + 1]:
        return params[idx + 1]
    else:
        print(flag + ' flag must include an option!')
        exit()


# main entry point
if ( __name__ == "__main__"):   
        
    Ispread = m_file_TESTBED_MODEL
    Tspread = m_file_TESTBED_SCNRO  #testbed data used for unit tests
 
    params = sys.argv
    if len(params) > 1:
        if 'help' in params[1].lower():
            print ('\nUSAGE: python', params[0], '[-i <Path to Infrastructure spreadsheet>] [-s <Path to Scenarios spreadsheet>]')
            exit()
        
        if '-i' in params:
            Ispread = optionReader(params, '-i')

        if '-s' in params:
            Tspread = optionReader(params, '-s')   
     
      
    myDATASET = LOAD_DATA (Ispread, Tspread, False, False )
    zonemap = INIT_TOPOLOGY(myDATASET, True ) 
 
    bDone = False
    while not(bDone):
        
       cmdline = input('>>> ')
       cmds = cmdline.split(' ')
       
       if cmds[0].lower() == 'help':
          print ('supported commands: disys | disfx | discap | shomap | shoip | shosys | path | surfaces | targets | exit')  
       elif cmds[0].lower() == 'exit' or cmds[0].lower() == 'quit':
          bDone = True
       elif cmds[0].lower().startswith('path'):
          do_zonepath(cmds, zonemap, True)       
       elif cmds[0].lower().startswith('targets'):
          do_zonetargets(myDATASET, cmds, True)
       elif cmds[0].lower().startswith('surfaces'):
          do_zonends (myDATASET, cmds, True)
       elif cmds[0].lower().startswith('shomap'):
           show_zonemap(zonemap )
       elif cmds[0].lower().startswith('shoip'):
           show_ip (myDATASET, cmds, False)
       elif cmds[0].lower().startswith('shosys'):
           show_sys(myDATASET, cmds )
       elif cmds[0].lower().startswith('disys'):
           do_disruptSYS(myDATASET, cmds, True)
       elif cmds[0].lower().startswith('disfx'):
           do_disruptFX (myDATASET, cmds, True)
       elif cmds[0].lower().startswith('discap'):
           do_disruptCAP (myDATASET, cmds, True)
       elif cmds[0].lower().startswith('attack'):
           do_traverse(myDATASET, zonemap, cmds, True)
       else:           
          print ('Say what?')

    print ('Exiting...')


    
    