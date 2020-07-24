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
imodel.py - Object classes for infrastructure data
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


class CTYPE:
    def __init__ (self, ctid, vendor, desc, typex, plat ):
        self.ctid = ctid
        self.vendor = vendor
        self.desc = desc
        self.typex = typex
        self.plat = plat
        self.vulnerability = []
        self.surface = []
        
    def getID(self):
        return self.ctid
    
    def getVendor(self):
        return self.vendor
    
    def getDesc(self):
        return self.desc
    
    def getType(self):
        return self.typex
    
    def getPlatform(self):
        return self.plat
    
    def addVulnerability (self, ventry):
        self.vulnerability.append (ventry)
        
    
    
    def link_4 (self, surfArray, trace=True ):
        for surf in surfArray:
            if (surf.getCTYPE() == self.ctid):
                if (trace):
                   print ('link_4: SURFACE', surf.getSurface(), 'added to CTYPE', self.ctid )
                self.surface.append (surf )      
                
    def getVulnerabilityList (self):
        return self.vulnerability

    def getSurfaceList(self):
        return self.surface
    
    def PP(self, verbose):
       if not (self.typex):
          print ('Component Description:', self.vendor, self.desc )
       else:
          print ('Component Description:', self.vendor, self.desc, self.typex )
          
       if (verbose):
         if self.vulnerability:   
           print ('Vulnerabilities:')
           for v in self.vulnerability:
               v.PP(False  )

class COMPONENT:
    def __init__ (self, cID, ctype, ipAddr, sys, crit, bEP):
        self.cID = cID
        self.ctype = ctype
        self.sysName = sys
        self.ipaddr = ipAddr
        self.crit = crit
        self.bEP = bEP
        self.system = None
        self.accessibility = -1
        self.susceptibility = -1
        
    def getID(self):
        return self.cID
    
    def getCtype(self):
        return self.ctype
    
    def getName(self):
        return self.ipaddr
    
    def getCTYPEID(self):
        if self.ctype:
            return self.ctype.getID()
        
    def getVendor(self):
        if self.ctype:
            return self.ctype.getVendor()
        
    def getPlatform(self):
        if self.ctype:
            return self.ctype.getPlatform()
        
    def isEP(self):
        return self.bEP
    
    def getDesc(self):
        if self.ctype:
            return self.ctype.getDesc()
    
    def getType(self):
        if self.ctype:
            return self.ctype.getType()
        
    def getZone(self):
        l = self.system.getLevel()
        z = self.system.getZone()
        return (str(l)+z)
    
    def getSysName (self):
        return self.sysName
    
    def getSystem(self):
        return self.system
    
    def getIPAddress(self):
        return self.ipaddr
    
    def getCriticality(self):  
        ret = []
        if self.system:
               ret = self.system.getCriticality().copy()
               ret.append(self.crit)
        
        return ret

    
    def link_2 (self, sArray, trace=False ):
        for s in sArray:
            if (s.getName() == self.sysName):
                if (trace):
                   print ('link_2: SYSTEM', s.getName(), 'added to COMPONENT', self.getDesc())
                self.system = s
                return            
    
    def getVulnerabilityList (self):
        if self.ctype:
            return self.ctype.getVulnerabilityList()
        
    def getCVEcount (self):
        if self.ctype:
            return len (self.ctype.getVulnerabilityList() )
    
    def getSurfaceList(self):
        if self.ctype:
            return self.ctype.getSurfaceList()
        
    def getAccessibility(self):
        if self.ctype:
            self.accessibility = len (self.ctype.getSurfaceList())
        return self.accessibility


    def getSusceptibility(self):
        if self.ctype:
            self.susceptibility = len (self.ctype.getVulnerabilityList())
        return self.susceptibility


    critsScore = [['cap MC', 50],['cap ME', 35],['cap MS', 20],
                  ['fx MC', 30],['fx ME', 25],['fx MS', 18],
                  ['sys MC', 26],['sys ME', 22],['sys MS', 15],
                  ['comp MC', 20],['comp ME', 15],['comp MS', 12]]
                 
    def getImpactScore (self ):
       ret = 0
       for c in self.getCriticality():
          for s in self.critsScore:
            if (c == s[0]):
                ret = ret + int(s[1])
                break
       return ret   
   
    
    def getSystemAffected(self):
        return self.sysName
    
    def getFunctionsAffected(self):
         fxlist = self.system.getFunctionList()
         fxnames = []
         for fx in fxlist:
             fxnames.append(fx.getName() )             
         if fxnames:
             return list (set(fxnames ))
                 
    def getCapabilitiesAffected (self):
         fxlist = self.system.getFunctionList()
         fxnames = []
         capset = set()
         for fx in fxlist:
             fxnames.append(fx.getName() )        
             capset.add(fx.getCapability() )        
             
         return list(capset)
        
    
    def PP(self, bTarget, verbose=True):
        print ('\n'+self.ipaddr, 'System:', self.sysName, 'CVE count:', self.getCVEcount(), 'Impact Score:', self.getImpactScore() ) 
        self.getCtype().PP(True )
        if bTarget:
            print ('\nSystem Affected:', self.getSystemAffected() )
            print ('Function(s) Affected:', self.getFunctionsAffected() )
            print ('Capabilit(ies) Affected:', self.getCapabilitiesAffected() )

    
class SYSTEM:
    def __init__ (self, name, desc, level, zone, crit ):
        self.name = name
        self.desc = desc
        self.level = level
        self.zone = zone
        self.crit = crit
        self.scrits = []

        self.function = []
        self.component = []
        self.fcrits = []

        self.critscore = 0
        self.bestcrits = []
        
    def getID(self):
        return self.name

    def getName(self):
        return self.name
    
    def getDescription(self):
        return self.desc
    
    def getLevel(self):
        return self.level
    
    def getZone(self):
        return self.zone
    
    def getFunctionList(self):
        return self.function
    
    def getComponentList(self):
        return self.component   
    
    def getCriticality(self ):
        if not(self.fcrits):
            return None          

        ret = self.fcrits.copy()
        ret.append(self.crit)
        return ret
    
    critsScore = [['cap MC', 50],['cap ME', 35],['cap MS', 20],
                  ['fx MC', 30],['fx ME', 25],['fx MS', 18],
                  ['sys MC', 26],['sys ME', 22],['sys MS', 15],
                  ['comp MC', 20],['comp ME', 15],['comp MS', 12]]
    
    def computeCriticality (self, critlist ):
        ret = 0
        if not(critlist):
            return ret       
        for j in critlist:
            for k in self.critsScore:
                if j == k[0]:
                    ret = ret + k[1]                   
        return ret    
    
    def assertCriticality(self, trace=True ):       
        
        if self.fcrits:
            if trace:
                print('SYSTEM', self.name, 'criticality already assigned.')
            return
        
        if not(self.function):
           print('WARNING! System', self.name, 'has no assigned function')

        if trace:
           print ('\nSYSTEM', self.name, 'supports', str(len(self.function)), 'functions')            

        self.bestscore = 0
        for j in self.function:
            testcrits = j.getCriticality()

            if (len(testcrits) > 2):
               print('WARNING! Invalid function criticality', testcrits)

            score = self.computeCriticality(testcrits)
            if trace:
                print ('checking FUNCTION', j.getName(), 'testcrits', testcrits, 'score', score)

            if score > self.bestscore:
                self.bestscore = score
                self.fcrits = testcrits
                if trace:
                    print ('SYSTEM', self.name, 'fcrits updated to', self.fcrits ) 
        return
  
       
    def link_3 (self, c_array, trace=False ):
        for c in c_array:
            if (c.getSysName() == self.name ):
                if (trace):
                   print ('link_3: COMPONENT', c.getDesc(), 'added to SYSTEM', self.name )
                self.component.append (c)
                
    def link_5 (self, rmap, sArray, trace=False ):
        for s in rmap:
            if (s.getSystem() == self.name ):
                sys = s.getFunction()
                for q in sArray:
                    if (q.getName() == sys):
                       if (trace):
                          print ('link_5: FUNCTION', s.getFunction(), 'added to SYSTEM', self.name )
                       self.function.append (q )
        return
       
    
    def PP(self, verbose=True ):
        print ('SYSTEM:', self.name )
        if (verbose):
           for e in self.component:
               e.PP(False  )
  
class FSMAP:
    def __init__ (self, function, system ):
        self.system = system
        self.function = function
        
    def getSystem(self):
        return self.system
    
    def getFunction(self):
        return self.function


class LOCATION:
    def __init__ (self, level, zone, facility, owner, access):
        self.level = level
        self.zone = zone
        self.facility = facility
        self.owner = owner
        self.access = access
        self.system = []
        
    def getLevel(self):
        return self.level
    
    def getZone(self):
        return self.zone
    
    def getZoneDesignation (self):
        return str(self.level)+self.zone
    
    def getFacility(self):
        return self.facility
    
    def getOwner(self):
        return self.owner
    
    def getAccess(self):
        return self.access
    
    def link_7 (self, r_array, trace=False ):
        for c in r_array:
            if (c.getLevel() == self.level ) & (c.getZone() == self.zone ):
                if (trace):
                   print ('link_7: SYSTEM', c.getName(), 'added to LOCATION', str(self.level), '-', str(self.zone))
                self.system.append (c)
                
    def getSystemList(self):
        return self.resources
    
    def PP(self, verbose=True):
        print ('\nLOCATION:', str(self.level), '-', str(self.zone), 'Facility:', self.facility)
        for e in self.system:
           e.PP(verbose )


class FX:
    def __init__(self, name, desc, capName, crit ):
        self.name = name
        self.desc = desc
        self.capName = capName
        self.crit = crit
        self.system = []
        self.capability = None
        self.fcrits = []
        
        self.cArray = []
        
    def getName(self):
        return self.name
    
    def getDescription(self):
        return self.desc
    
    def getCriticality(self ):
        if not(self.capability):
            return None 
        
        if not (self.fcrits):
           self.fcrits = [self.capability.getCriticality()]
           self.fcrits.append (self.crit)
        return self.fcrits
    
    def getSystemList(self):
        return self.system    
    
    def getCapability(self):
        return self.capName
 
    def link_6 (self, r_array, trace=False ):
        for r in r_array:
            if (self in r.getFunctionList() ):
                if (trace):
                   print('link_6: SYSTEM', r.getName(), 'added to FUNCTION', self.name)
                self.system.append (r)
    
    def link_8 (self, capArray, trace=False ):
        for c in capArray:
            if (c.getName() == self.capName):
                if (trace):
                   print ('link_8: FUNCTION', self.name, 'assigned to CAPABILITY', c.getName() )
                self.capability = c #.append (c)
                return
      
    def assertCriticality(self, trace):  
        if self.fcrits:
            if trace:
                print ('FUNCTION', self.name, 'criticalty already set.')
            return

        self.fcrits = [self.capability.getCriticality()]
        self.fcrits.append (self.crit)
        if trace:
            print ('FUNCTION', self.name, 'criticality set to', self.fcrits )
        return


    def PP(self, verbose=True):
        print ('\nFUNCTION:', self.name, 'CAPABILITY:', self.capName, 'Criticality:', self.fcrits)
        if (verbose):
           for e in self.system:
               e.PP(verbose )


class CAPABILITY:
    def __init__(self, name, desc, crit ):
        self.name = name
        self.desc = desc
        self.crit = crit
        self.function = []
        
    def getID(self):
        return self.name

    def getName(self):
        return self.name
    
    def getDescription(self):
        return self.desc
    
    def getCriticality(self):
        return self.crit
   
    def link_9 (self, s_array, trace=False ):
        for s in s_array:
            if (self.name == s.getCapability() ):
                if (trace):
                   print ('link_9: FUNCTION', s.getName(), 'added to CAPABILITY', self.name)
                self.function.append (s)
                
    def getFunctionList(self):
        return self.function
    
    def PP(self, verbose=True):
        print ('\nCAPABILITY:', self.name, 'Criticality:', self.crit)
        for e in self.function:
           e.PP(verbose ) 

class SURFACE:
    def __init__(self, ctype, surface, access ):
        self.ctype = ctype
        self.surfaceName = surface
        self.access = access
    
    def getCTYPE(self):
        return self.ctype
    
    def getSurface(self):
        return self.surfaceName
    
    def getAccess(self):
        return self.access
    
    def PP(self, verbose=False):
        print ('Surface:', self.surfaceName, 'Access:', self.access )


class CONNECTION:
    def __init__(self, cnt, sourcesys, destsys, flowflag, rtrNm, rtrTyp, cflag ):
        self.cnt = cnt
        self.srcsys = sourcesys
        self.dstsys = destsys
        self.flowflag = flowflag
        self.rtrNm = rtrNm
        self.rtrTyp = rtrTyp
        self.cflag = cflag
        self.ctype = []

    def getSrcSys (self):
        return self.srcsys
    
    def getDesSys (self):
        return self.dstsys
    
    def isOneway (self):
        if (self.flowflag == 'oneway'):
            return True
        return False
    
    def getFlowflag(self):
        return self.flowflag
    
    def getRouterName(self):
        return self.rtrNm
    
    def getRouterType(self):  #  field value shoud map to CTYPE for router
        return self.rtrTyp
    
    def mapCTYPE(self, ctypelist):
        for t in ctypelist:
            if (t.getID() == self.rtrTyp):
               self.ctype = t
               return        
        print ('Warning: CTYPE of controlled interface', self.cnt ,' not recognized')    
    
    def isPoned(self):
        if (self.cflag > 0):
            return True
        return False
    
    def getSrcZone(self, sysList ):
        for s in sysList:
            if s.getName() == self.srcsys:
                return s.getZone()
            
    def getSrcLevel(self, sysList ):
        for s in sysList:
            if s.getName() == self.srcsys:
                return s.getLevel()
        
    def getDstZone(self, sysList ):
        for s in sysList:
            if s.getName() == self.srcsys:
                return s.getZone()
            
    def getDstLevel(self, sysList ):
        for s in sysList:
            if s.getName() == self.srcsys:
                return s.getLevel()
            
    def getDstZoneID (self, sysList ):
        for s in sysList:
            if s.getName() == self.dstsys:
                return str(str(s.getLevel())+s.getZone())
        print ('Warning: Connection', self.cnt, 'destination zone unknown.' )
        return
    
    def PP(self):
        print ('ID:', self.cnt, self.srcsys, '-->', self.dstsys)
        print ('Flow:', self.flowflag, ' Router Name:', self.rtrNm, ' CTYPE:', self.rtrTyp, ' Powned:', self.cflag )
    
    