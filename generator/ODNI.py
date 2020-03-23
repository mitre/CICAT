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


ODNI.py - Implements ODNI cyber framework

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import openpyxl
import random
#from collections import defaultdict #, OrderedDict

class STAGE():
    def __init__ (self, name, desc):
        self.name = name
        self.desc = desc
        self.objectives = []
        self.tactics = []
        
    def getName(self):
        return self.name
    
    def getDesc(self):
        return self.desc
    
    def addObjective(self, objective):
        self.objectives.append (objective)
        
    def addTactic(self, tactic):
        self.tactics.append (tactic)
        
    def getObjectives(self):
        return self.objectives
    
    def getTactics(self):
       return self.tactics
   
    def selectTactic (self, hint):
        return random.choice(self.tactics)
        
    def getTacticSequence (self):
       ret = []
       for x in self.objectives:
          ret.append(x.selectTactic(hint=''))        
       return ret    
           
    def PP(self):
        print ('STAGE:', self.name)
        for o in self.objectives:
            o.PP()
        for t in self.tactics:
            t.PP()

class OBJECTIVE():
    def __init__ (self, name, desc, stage):
        self.name = name
        self.desc = desc
        self.stage = stage
        self.tactics = []
        
    def getName(self):
        return self.name
    
    def getDesc(self):
        return self.desc
    
    def getStage(self):
        return self.stage
    
    def addTactic(self, tactic):
        self.tactics.append(tactic)
        
    def getTactics(self):
        return self.tactics
    
    def selectTactic(self, hint):
        if not(self.tactics):
            return

        if (self.name != 'Exfiltrate'):
            return random.choice(self.tactics)
        
        tname = ''
        if (hint == 'Windows' or hint == 'Linux' or hint == 'macOS'):
            tname = 'exfiltration'
        else:
            tname = random.choice (['effects', 'network-effects', 'remote-service-effects'])
        
        for j in self.tactics:
            if (j.getName() == tname):
                return j

    
    def PP(self):
        print (' OBJECTIVE:', self.name)
    

class TACTIC():
    def __init__ (self, name, desc, objective, stage ):
        self.name = name
        self.desc = desc
        self.stage = stage
        self.ttps = []
        self.objective = objective
        
    def getName(self):
        return self.name
    
    def getDesc(self):
        return self.desc   
        
    def getStage(self):
        return self.stage
    
    def addTTP(self, ttp):
        self.ttps.append(ttp)
    
    def getTTPs(self):
        return self.ttps
    
    def getObjective(self):
        return self.objective
    
    def selectTTP(self, platform ):
        
        if not(self.ttps):
            return self.ttps

        if not(platform):
            return random.choice(self.ttps)

        plist = []
        for k in self.ttps:  
            if (k.getPlatform()):
                if (platform in k.getPlatform() ):
                    plist.append(k)       
                
        if not(plist):
           return plist  
       
        return random.choice(plist)
    
    def getTTPCount (self, platform):
        if not(self.ttps):
            return 0

        if not(platform):
            return len (self.ttps)

        plist = []
        for k in self.ttps:  
            if (k.getPlatform()):
                if (platform in k.getPlatform() ):
                    plist.append(k)       
                
        if not(plist):
           return 0       
       
        return len(plist)        
        
    def PP(self):
        print (' TACTIC:', self.name, 'TTPs:', str(len(self.ttps)))
        for t in self.ttps:
          print(' ', t.getTECHID(), ':', t.getName() )
 

m_STAGES = []
m_OBJECTIVES = []
m_TACTICS = []

def findTactic(name):
    for t in m_TACTICS:
        if (t.getName() == name):
            return t
                   
def loadODNI(filename ):    
  book = openpyxl.load_workbook(filename, data_only=True) 
  sheet = book['Stages']
  rows = sheet.rows
  for row in rows:
    m_STAGES.append (STAGE (row[0].value, row[1].value ) )

  sheet = book['Objectives']
  rows = sheet.rows
  for row in rows:
    m_OBJECTIVES.append (OBJECTIVE (row[0].value, row[1].value, row[2].value ) )
      
  sheet = book['Tactics']
  rows = sheet.rows
  for row in rows:
    m_TACTICS.append (TACTIC (row[0].value, row[1].value, row[2].value, row[3].value ) )    
    
  del (m_STAGES[0])  
  del (m_OBJECTIVES[0])
  del (m_TACTICS[0])

def augmentTTPs(tacticname, ttplist):
    tactic = findTactic(tacticname)
    if tactic:
        for j in ttplist:
            tactic.addTTP (j)         

def mapTTPs(TTPlist):
  for t in TTPlist:
       tlist = t.getTactic()
       if (tlist):
          for c in tlist:
             entry = findTactic(c)
             if (entry):
                 entry.addTTP(t)

  for x in m_STAGES:
     for o in m_OBJECTIVES:
        if (x.getName() == o.getStage() ):
            x.addObjective (o)           
     for t in m_TACTICS:
         if (x.getName() == t.getStage() ):
             x.addTactic(t)
             
  for t in m_TACTICS:
     obj = t.getObjective()
     if (obj):      
        for o in m_OBJECTIVES:
         if (obj == o.getName()):
             o.addTactic(t)

  return m_STAGES
             
def ttpSequenceByStages (stages, platform, trace):  
    ret = []
    for p in stages:  
      if (trace):
         print ('\nStage:', p.getName())
      for o in p.getObjectives():
          if (trace):
             print ('\nObjective:', o.getName() )
          for t in o.getTactics():
              if (trace):
                 print ('Tactic:', t.getName ())
              ttpx = t.selectTTP(platform )
              if (ttpx):
                 if (trace):
                    print ('EXAMPLE:', ttpx.getTECHID(), ':', ttpx.getName(), '-', ttpx.getDesc() )
                 ret.append(ttpx)
              else:
                 if (trace):
                    print ('  ***  NO TTPS IDENTIFIED  ***')
    return ret 

def findPlatformByName(entry):
    if (entry=='Platform:Linux'):
        return 'Linux'
    elif (entry == 'Platform:macOS'):
        return 'macOS'
    elif (entry == 'Platform:Windows'):
        return 'Windows'
    elif (entry == 'Platform:Android'):
        return 'Android'
    elif (entry == 'Platform:iOS'):
        return 'iOS'   
    return None

def success(val):
    if random.random() > val:
        return False   
    return True

def nextstep(listx, step):#, pSuc):
    if (step < len(listx)-1):
       return step + 1

    return -1 


def findObjectiveByName( name):
    for o in m_OBJECTIVES:
        if (o.getName() == name):
            return o


def printTTP (ttp):
    print ('\n' + ttp.getTECHID(), ':', ttp.getName() ) #, '-', ttp.getDesc() )
    print ('URL:', ttp.getURL() )
    print ('Platform(s):', ttp.getPlatform(), 'Tactic[s]:', ttp.getTactic() )
    print ('Tag(s):', ttp.getTags())
    
