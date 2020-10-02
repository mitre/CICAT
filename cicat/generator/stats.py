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
stats.py - Routines to generate sorted lists and counts
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


from collections import defaultdict

"""
TAG USAGE STATISTICS
"""

x_TYPES = defaultdict(list)
x_TACTICS = defaultdict(list)
x_PLATFORMS = defaultdict(list)

x_ACTTAGS = defaultdict(list)
x_TTPTAGS = defaultdict(list)
x_MITTAGS = defaultdict(list)
x_MALTAGS = defaultdict(list)
x_TOLTAGS = defaultdict(list)

def TAGS_INDEX (dataset, trace):
    
   if trace:
        print ('Initializing X_TYPES index..')
    
   for a in dataset['ATKGROUPS']:
       x_TYPES[a.getType()].append(a)

   for a in dataset['ATKTOOL']:
       x_TYPES[a.getType()].append(a)       

   for a in dataset['ATKMALWARE']:
       x_TYPES[a.getType()].append(a)
       
   for a in dataset['ATT&CK']:
       x_TYPES[a.getType()].append(a)
       
   for a in dataset['ATKMITIGATION']:
       x_TYPES[a.getType()].append(a)
       
   if trace:
        print ('Initializing X_TACTICS index..')
              
   for t in dataset['ATT&CK']:
       tctlist = t.getTactic()
       if (tctlist):
          for c in tctlist:
             x_TACTICS[c].append(t)
   if trace:
        print ('Initializing X_PLATFORMS index..')

   for t in dataset['ATT&CK']:
       platlist = t.getPlatform()
       if (platlist):
           for p in platlist:
              x_PLATFORMS[p].append(t)

   for x in dataset['ATKTOOL']:   
      platlist = x.getPlatform()
      if (platlist):
          for p in platlist:
             x_PLATFORMS[p].append(x)
             
   for mal in dataset['ATKMALWARE']:   
      platlist = mal.getPlatform()
      if (platlist):
          for p in platlist:
             x_PLATFORMS[p].append(mal)

   if trace:
        print ('Initializing X_ACTTAGS index..')
   
   for j in dataset['ATKGROUPS']:
       for tag in j.getTags():
           x_ACTTAGS[tag].append(j)

   if trace:
        print ('Initializing X_TTPTAGS index..')
       
   for j in dataset['ATT&CK']:
       for tag in j.getTags():
           x_TTPTAGS[tag].append(j)

   if trace:
        print ('Initializing X_MITTAGS index..')    
       
   for j in dataset['ATKMITIGATION']:
        for tag in j.getTags():
            x_MITTAGS[tag].append(j)

   if trace:
        print ('Initializing X_TOOLTAGS index..')           
        
   for j in dataset['ATKTOOL']:
        for tag in j.getTags():
            x_TOLTAGS[tag].append(j)

   if trace:
        print ('Initializing X_MALTAGS index..')                   
        
   for j in dataset['ATKMALWARE']:
        for tag in j.getTags():
            x_MALTAGS[tag].append(j)
                   
   if trace:
      print ('TAGs indexed..')


""" 
INFRASTRUCTURE STATISTICS
"""
#returns locations by decreasing system counts
def sortLocationsbySize(dataset, minsize ):
    
    raw_t = []
    sorted_t = []
       
    for j in dataset['LOCATION']:
        if j.system and (len(j.system) > minsize):
          
          raw_t.append([len(j.system), j.getZoneDesignation() ])
           
    sorted_t = sorted(raw_t, key=lambda raw: raw[0], reverse=True  )
    
    ret = []
    for l in sorted_t:
        ret.append(l[1])
        
    return ret

#returns zones by decreasing connections
def sortZonesbyConnections (zonemap):

    raw_t = []
    sorted_t = []

    for z in zonemap.keys():
        raw_t.append ([z, len(zonemap[z])])
        
    sorted_t = sorted(raw_t, key=lambda raw: raw[1], reverse = True )
    
    ret = []
    for l in sorted_t:
        ret.append(l[0])

    return ret

#returns systems by decreasing function usage
def sortSystemsbyFunction(dataset):
    
    raw_t = []
    sorted_t = []
    
    tdix = defaultdict(list)
    for f in dataset['FSMAP']:
        if f.getSystem():
           tdix[f.getSystem()].append (f.getFunction() )
        
    for s in tdix.keys():
        raw_t.append( [s, len(tdix[s]) ] )

    sorted_t = sorted(raw_t, key=lambda raw: raw[1], reverse = True )
    
    ret = []
    for l in sorted_t:
        ret.append(l[0])

    return ret

"""
SCENARIO STATISTICS
"""

#returns scenarios sorted by attack path length
def sortByAttackPathsbyLength(statsdata):
    
    raw_t = []
    sort_t = []
    
    for s in statsdata:
        raw_t.append ( [s['name'], len(s['path']) ])
    
    sort_t = sorted (raw_t, key=lambda raw: raw[1], reverse=True )
    
    ret = []
    for l in sort_t:
        ret.append(l[0])
        
    return ret

#returns list of IPs most visited by scenarios
def sortByVisitedNode(statsdata):
    
    raw_t = []
    sort_t = []
    
    ipx = defaultdict(list)
    
    for s in statsdata.keys():
        entry = statsdata[s][0]
        ap = entry['path']
        for ip in ap:
            ipx[ip].append ('X')
            
    for k in ipx.keys():
        raw_t.append ( [k, len(ipx[k])] )
           
    sort_t = sorted (raw_t, key=lambda raw: raw[1], reverse=True )
    
    ret = []
    for l in sort_t:
        ret.append(l[0])
        
    return ret

#returns list of entrypoints sorted by usage
def sortByEntrypointSuccesses(statsdata):
    
    raw_t = []
    sort_t = []
    
    epdata = defaultdict(list)
    
    for s in statsdata:
        ep = s.split('EP')
        epdata[ep[1]].append(s)
        
    for ex in epdata.keys():
        raw_t.append([ex, len(epdata[ex])])
        
    sort_t = sorted (raw_t, key=lambda raw: raw[1], reverse=True )
    
    ret = []
    for l in sort_t:
        ret.append(l[0])
        
    return ret
    
#returns list of TTPs sorted by usage
def sortByTTPUsage(statsdata):
    
    raw_t = []
    sort_t = []
    
    ttpdata = defaultdict(list)
    
    for s in statsdata.keys():
        entry = statsdata[s][0]
        for seq in entry['ttps']:
           for q in seq:
              ttpdata[q].append('X')
    
    for k in ttpdata.keys():
        raw_t.append([k, len(ttpdata[k])])
        
    sort_t = sorted (raw_t, key=lambda raw: raw[1], reverse=True )
    
    ret = []
    for l in sort_t:
        ret.append(l[0])
        
    return ret    

def sortActorsBySophistication (dataset):    
    raw_t = []
    sort_t = []
    
    for t in dataset['ATKGROUPS']:
        raw_t.append ([t.getGroupID(), t.getSophisticationLevel()])
        
    sort_t = sorted (raw_t, key=lambda raw: raw[1], reverse=True )
    
    ret = []
    for s in sort_t:
        ret.append(s[0])
        
    return ret

def countTTPsByTactic (dataset, tactic, groupID):
    for t in dataset['ATKGROUPS']:
      if t.getGroupID() == groupID:
          ttplist = []
          pb = t.getPlaybook()
          for x in pb:
              if x[0].typex == 'attack-pattern': 
                  ttplist.append (x[0])
          ret = 0
          for t in ttplist:
             if (tactic in t.getTactic()):
                ret = ret + 1               
          return ret

