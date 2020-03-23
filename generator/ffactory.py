# -*- coding: utf-8 -*-
"""
Created on Mon Feb 17 12:08:22 2020

@author: JWYNN
"""
import sys
import re
from collections import defaultdict
from loaddata import LOAD_DATA, LOAD_TTP_SUPPLEMENT, LOAD_ATK4ICS, LOAD_ACTOR_PROFILES
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS #, m_file_EXTENSIONS, m_file_ODNI 

m_byTacticDict = defaultdict(list)
m_byPlatformDict = defaultdict(list)
m_byActorDict = defaultdict(list)
m_bySurfaceDict = defaultdict(list)

class FILTER_FACTORY():
    def __init__ (self, trace ):
        self.trace = trace
        if self.trace:
            print ('FILTER_FACTORY constructed..')
        
    def getFilter (self, filtertype, tag, dataset ):

        if (filtertype == 'byTactic'):
            if m_byTacticDict[tag]:
                return m_byTacticDict[tag]
            else:
                m_byTacticDict[tag] = FILTER_byTactic (tag, dataset, self.trace)   # tag is tactic name
                return m_byTacticDict[tag]
            
        elif (filtertype == 'byPlatform'):
            if m_byPlatformDict[tag]:
                return m_byPlatformDict[tag]
            else:
                m_byPlatformDict[tag] = FILTER_byPlatform (tag, dataset, self.trace)  # tag is platform type
                return m_byPlatformDict[tag]
            
        elif (filtertype == 'byActor'):
            if m_byActorDict[tag]:
                return m_byActorDict[tag]
            else:
                m_byActorDict[tag] = FILTER_byActor (tag, dataset, self.trace)  # tag is actorname
                return m_byActorDict[tag]

        elif (filtertype == 'bySurface'):
            if m_bySurfaceDict[tag]:
                return m_bySurfaceDict[tag]
            else:
                m_bySurfaceDict[tag] = FILTER_bySurface (tag, dataset, self.trace)  # tag is surfacename
                return m_bySurfaceDict[tag]

        else:
            if self.trace:
                print ('WARNING! FILTER_FACTORY: unrecognized filter:', filtertype )
       

class BASEFILTER():
    def __init__ (self, tag, dataset, trace):
      self.tag = tag
      self.dataset = dataset
      self.trace = trace     
      self.ttplist = []

    def getTTPList(self):
        return self.ttplist
    
    def getTTPSet(self):
        return set(self.ttplist) 
    
    # setTTPList() used to initialize the filter for the deny tactic, which is loaded as supplimental TTP data
    def setTTPList(self, ttplist):
        self.ttplist = ttplist.copy()


class FILTER_byTactic (BASEFILTER):
    def __init__ (self, tag, dataset, trace ):
        BASEFILTER.__init__(self, tag, dataset, trace )
        if self.trace:
            print ('byTactic Filter constructed..')      
        for ttp in dataset:
            if not ttp.getTactic():
                if trace:
                   print ('WARNING! No tactic specified', ttp.getTECHID(), ':', ttp.getName() )
                continue
            
            if self.tag in ttp.getTactic():
                self.ttplist.append (ttp)
        return   


class FILTER_byPlatform (BASEFILTER):
    def __init__(self, tag, dataset, trace):
        BASEFILTER.__init__(self, tag, dataset, trace)
        if self.trace:
            print ('byPlatform Filter constructed..')    
        for ttp in dataset:
            if not ttp.getPlatform():
               if trace:
                  print ('WARNING! No platform specified', ttp.getTECHID(), ':', ttp.getName() )
               continue

            if self.tag in ttp.getPlatform():
                self.ttplist.append (ttp)
        return

    
class FILTER_byActor(BASEFILTER):
    def __init__ (self, tag, dataset, trace):
        BASEFILTER.__init__(self, tag, dataset, trace)
        if self.trace:
            print ('byPlatform Filter constructed..')
            
        for act in dataset:
            if self.tag == act.getGroupID():
                self.ttplist = act.getTTPList().copy()               
                return


class FILTER_bySurface(BASEFILTER):
    def __init__ (self, tag, dataset, trace):
        BASEFILTER.__init__(self, tag, dataset, trace)
        if self.trace:
            print ('bySurface Filter constructed..')
            
        p = re.compile(tag, re.IGNORECASE)
        for ttp in dataset:
            if not(ttp.getDesc()):
                if trace:
                    print ('WARNING! TTP has no description', ttp.getTECHID(), ':', ttp.getName() )
                continue
            
            if p.search (ttp.getDesc().casefold() ):
                self.ttplist.append (ttp)
          
        return
           


def getTTPs(ffactory, dataset, tactic, platform, actor):
  
    if not(tactic):
        return 

    rset = set()
    l1 = ffactory.getFilter('byTactic', tactic, dataset['ATT&CK'] + dataset['ATK4ICS TTPs']).getTTPSet()   
    rset = l1     
    
    if platform:
       l2 = ffactory.getFilter('byPlatform', platform, dataset['ATT&CK'] + dataset['ATK4ICS TTPs'] ).getTTPSet() 
       rset = rset & l2
    
    if not(tactic == 'deny') and actor:
       l3 = ffactory.getFilter('byActor', actor, dataset['ATKGROUPS'] ).getTTPSet()
       rset = rset & l3
           
    return list(rset)


def getTTPsforCTYPE(ffactory, dataset, ctypeID):
    
    slist = []
    for c in dataset['CTYPE']:
        if c.getID() == ctypeID:
            slist = c.getSurfaceList()
            break
        
    if not(slist):
       return
   
    fullttplist = dataset['ATT&CK'] + dataset['TTP_SUP']
 
    rset = set()
    for surf in slist:
        sset = ffactory.getFilter('bySurface', surf.getSurface(), fullttplist ).getTTPSet()
        rset = rset | sset
        
    return list(rset)  
    
def showTTPs (title, ttplist):
    if ttplist:
       print ('\n' + title, '(' + str(len(ttplist)), 'entries)')
       for t in ttplist:
           print (t.getTECHID(), ':', t.getName())
    else:
       print ('\n' + title, '(no entries)') 


def INIT_FILTERS (ffactory, dataset):
    
    platlist = ['Windows', 'Linux', 'macOS', 'ICS']    
    tactlist = ['initial-access', 'discovery', 'privilege-escalation', 'credential-access', 'collection', 'execution', 
                'lateral-movement', 'persistence', 'exfiltration',  'defense-evasion', 'command-and-control', 
                'inhibit-response-function', 'impair-process-control', 'impact'] #, 'deny']

    # build tactic and platform and surface filters to include ATT&CK and the TTP_SUP set of TTPs
    fullttplist = dataset['ATT&CK']  + dataset['ATK4ICS TTPs']
    
    for t in tactlist:
        ffactory.getFilter('byTactic', t, fullttplist ) 
        
    for p in platlist:
        ffactory.getFilter('byPlatform', p, fullttplist )    
        
    for surf in dataset['SURFACE']:
        ffactory.getFilter('bySurface', surf.getSurface(),  fullttplist )        

    for actor in dataset['ATKGROUPS']:
        ffactory.getFilter ('byActor', actor.getGroupID(), dataset['ATKGROUPS'] )

    return       


def FILTER_TEST1 (ffactory, dataset, platlist):
    
    tactlist = ['initial-access', 'discovery', 'privilege-escalation', 'credential-access', 'collection', 'execution', 
                'lateral-movement', 'persistence', 'exfiltration',  'defense-evasion', 'command-and-control', 'impact',
                'inhibit-response-function', 'impair-process-control' ]
   
    print ('\n' )
    print ('>> Platform Filter Tests <<')      
    
    for t in tactlist:    
        showTTPs ('FILTER TEST: '+ t + ', none, none', getTTPs(ffactory, dataset, t, '', '') )     
        for p in platlist: 
          showTTPs ('FILTER TEST: ' + t + ', ' + p + ', none', getTTPs(ffactory, dataset, t, p, '') )     

def FILTER_TEST2 (ffactory, dataset, actorlist):
    
    tactlist = ['discovery', 'execution', 'lateral-movement', 'persistence', 'defense-evasion', 'command-and-control', 'impact']
    
    print ('\n' )
    print ('>> Threat Actor Profile Tests <<')      
                  
    for a in actorlist:
        for t in tactlist:
           showTTPs ('FILTER TEST: ' + t + ', Linux, ' + a, getTTPs(ffactory, dataset, t, 'Linux', a ) )  
           showTTPs ('FILTER TEST: ' + t + ', Windows, ' + a, getTTPs(ffactory, dataset, t, 'Windows', a ) )  
    
    
def FILTER_TEST3 (ffactor, dataset, ctypelist):

    print ('\n' )
    print ('>> Attack Surface Filter Tests <<')   
    

    for s in ctypelist:
       surflist = []
       for x in dataset['SURFACE']:
           if x.getCTYPE() == s:
               surflist.append(x.getSurface())
        
       print ('\nSurfaces list for ' + s + ' (' + str(len(surflist)) + ' TTPs):', surflist )
       showTTPs ('Maps to', getTTPsforCTYPE(ffactory, dataset, s) )    


    
def FILTER_TEST4 (ffactory, dataset):
        
    print ('\n' )
    print ('>> Attack Surfaces Frequency Distribution <<')   
    print ('\n' )

    slist = []
    for k in m_bySurfaceDict.keys():
        filtr = m_bySurfaceDict[k]
        slist.append ([len(filtr.getTTPList() ), k] )
        
    for l in sorted (slist, reverse=True):
        print (str(l[0]), 'TTPs contain tag:', l[1])
        
    return


def FILTER_TEST5 (ffactory, dataset):
    
    ttplist = []
    for k in m_bySurfaceDict.keys():
        filtr = m_bySurfaceDict[k]
        flist = filtr.getTTPList()
        for f in flist:
           ttplist.append( f.getTECHID() )
        
    ttpset = set(ttplist)
    
    allist = []
    for q in dataset['ATT&CK']:
        allist.append(q.getTECHID())
        
    allset = set (allist)
    
    diffset = allset - ttpset
    difflist = list(diffset)
    
    print ('\n' )
    print ('>> Surface Filter Exclusion Test <<')      
    
    print ('There are', len(difflist), 'TTPs not referenced by keyword:')
    
    for d in difflist:
        for a in dataset['ATT&CK']:
            if a.getTECHID() == d:
                print (a.getTECHID(), ':', a.getName(), 'Tactic:', a.getTactic(), 'Platform:', a.getPlatform(), 'URL:', a.getURL() )
                break         

    return
    

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
    LOAD_TTP_SUPPLEMENT(myDATASET)
    
    LOAD_ATK4ICS (myDATASET, '..\\data\ATK4ICS.xlsx' )
    LOAD_ACTOR_PROFILES (m_file_INFRASTRUCTURE, myDATASET, ['SCADACAT', 'RedCanary', 'APT28', 'APT1', 'OilRig', 'Lazarus Group', 'Leviathan'])
 
    
    ffactory = FILTER_FACTORY(False )
    INIT_FILTERS (ffactory, myDATASET)
    
    FILTER_TEST1 (ffactory, myDATASET, ['Windows', 'Linux', 'ICS']  )  
    FILTER_TEST2 (ffactory, myDATASET, ['RedCanary', 'APT28', 'OilRig', 'Lazarus Group'])
    FILTER_TEST4 (ffactory, myDATASET)
    FILTER_TEST3 (ffactory, myDATASET, ['C004', 'C005', 'C006', 'C007', 'M009', 'ICS00'] )

    
    print ('End of run')
    
    