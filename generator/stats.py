# -*- coding: utf-8 -*-
"""
:::::::::::::::::::::::::::::::::::::  MITRE CRP PROJECT  :::::::::::::::::::::::::::::::::::::::

                                            NOTICE

This software (or technical data) was produced for the U. S. Government under contract 355358
with Brookhaven National Laboratory, and is subject to the Rights in Data-General Clause 52.227-14 (MAY 2014) or (DEC 2007).

The following copyright notice may be affixed after receipt of written approval from the Contracting Officer.
Please contact the Contracts Management Office for assistance with obtaining approval or identifying the correct clause.
If the contract has Clause 52.227-14, Alt. IV, written approval is not required and the below copyright notice may be affixed.

(c) 2020 The MITRE Corporation. All Rights Reserved.


stats.py - returns assorted analytics 


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

