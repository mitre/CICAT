# -*- coding: utf-8 -*-
"""
:::::::::::::::::::::::::::::::::::::  MITRE CICAT PROJECT  :::::::::::::::::::::::::::::::::::::::

topology.py - Builds network topology using CONNECTION table input

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


import sys
#import random
from collections import defaultdict
from loaddata import LOAD_DATA
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS # m_file_ODNI, m_file_EXTENSIONS 

m_topology = defaultdict (list)
m_zoneCIs = defaultdict (list)
m_zoneMMap = defaultdict(list)
m_zoneTopo = defaultdict (list)

def addLeveltoTopo (level):
    if not(m_zoneTopo[level]):
        m_zoneTopo[level] = []
        
def addZonetoTopo(level, zone):
    addLeveltoTopo(level) 
    m_zoneTopo[level].append ([level, zone])
        
def zonesInLevel(level):
    if m_zoneTopo[level]:
        return m_zoneTopo[level]

    print ('Unrecognized security level:', str(level) )
    return []
        
def initZoneList(dataset ):
    for cx in dataset['LOCATION']:        
        lvl = cx.getLevel()
        zon = cx.getZone()
        addZonetoTopo(lvl,zon)

def getSystemTopology(dataset, sysName):
    topo = [sysName]
    iplist = []
    for sysm in dataset['SYSTEM']:
        if (sysm.getName() == sysName):
            for c in sysm.getComponentList():
                iplist.append(c.getIPAddress() ) 
    topo.append(iplist)
    return topo

def getZoneTopology(dataset, level, zone ):
    topo = [[level, zone]]
    for sysm in dataset['SYSTEM']:
        if (sysm.getLevel() == level) and (sysm.getZone() == zone):
            topo.append(getSystemTopology(dataset, sysm.getName() ))          
    return topo

def getLevelTopology (dataset, level ):
    topo =[]
    zones = []
    for loc in dataset['LOCATION']:
        if (loc.getLevel() == level):
            zones.append (loc.getZone())           

    for z in zones:
        topo.append(getZoneTopology(dataset, level, z ))       
    return topo

def buildZoneMap(systemList, zoneCIs):
    for j in zoneCIs.keys():
        for ci in zoneCIs[j]:
           m_zoneMMap[j].append(ci.getDstZoneID(systemList ))
           
#    print('buildZoneMap:', m_zoneMMap)
    return m_zoneMMap    

def INIT_TOPOLOGY (dataset, trace):

    print ('Initalizing topology...')
    
    initZoneList (dataset)
 
    if trace:
        print ('Initializing Level Topologies..')
        
    for level in m_zoneTopo.keys():
       m_topology[level] = getLevelTopology(dataset, level  )
        
    if trace:
        print ('Initializing network routing..')

    for k in dataset['CONNECTION']:
        lvl = k.getSrcLevel(dataset['SYSTEM'])
        zon = k.getSrcZone(dataset['SYSTEM'])
        ztx = str(str(lvl)+zon)
        m_zoneCIs[ztx].append(k) 
         
    return buildZoneMap (dataset['SYSTEM'], m_zoneCIs)   


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
        
    Ispread = m_file_INFRASTRUCTURE
    Tspread = m_file_SCENARIOS
 
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


    print ('End of run')
