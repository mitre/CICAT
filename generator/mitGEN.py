
"""
:::::::::::::::::::::::::::::::::::::  MITRE CRP PROJECT  :::::::::::::::::::::::::::::::::::::::

                                            NOTICE

This software (or technical data) was produced for the U. S. Government under contract 355358
with Brookhaven National Laboratory, and is subject to the Rights in Data-General Clause 52.227-14 (MAY 2014) or (DEC 2007).

The following copyright notice may be affixed after receipt of written approval from the Contracting Officer.
Please contact the Contracts Management Office for assistance with obtaining approval or identifying the correct clause.
If the contract has Clause 52.227-14, Alt. IV, written approval is not required and the below copyright notice may be affixed.

(c) 2020 The MITRE Corporation. All Rights Reserved.



mitGEN.py - Utility for selecting 800-53 controls

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

#from collections import defaultdict
from stats import sortByEntrypointSuccesses, sortByTTPUsage, sortByVisitedNode, sortActorsBySophistication, countTTPsByTactic # sortAttackPathsbyLength, sortLocationsbySize, 


def showNode (dataset, ipaddr, bTarget, verbose ):
    for j in dataset['COMPONENT']:
        if ipaddr == j.getIPAddress():
            if verbose:
               j.PP(bTarget, True  )
            else:
               j.PP(bTarget, False )
            
            return
            
def showTechnique(ttpobj, verbose=True):
    print ('\n'+ttpobj.getTECHID()+' : '+ttpobj.getName())
    print ('URL:', ttpobj.getURL() )
    print ('Tactic(s):', ttpobj.getTactic() )
    if verbose:
       print ('Details:', ttpobj.getDesc().encode('utf8').decode('utf8'))   
    else:
       print ('Tag(s):', ttpobj.getTags())
    return

def showMitigation (ttpobj ):
    mitlist = ttpobj.getCOA()
    for m in mitlist:
        print ('\n'+m[0].getTECHID()+' : '+m[0].getName() )
        print ('Mitigation:', m[0].getDesc().encode('utf8').decode('utf8') )
        return
          
def showDetection (ttpobj ):          
    print ('\n'+ttpobj.getTECHID()+' : '+ttpobj.getName() )
    if ttpobj.getDET():
       print ('Forensics:', ttpobj.getDET().encode('utf8').decode('utf8') )
    else:
       print ('No forensic markers identified.')
    return    
          
def showActor (dataset, Aname, verbose):
    for j in dataset['ATKGROUPS']:
         if j.getName() == Aname:
             print ('\nGroup ID:', j.getGroupID(), 'Name:', j.getName(), 'Sophistication:', j.getSophisticationLevel() )
             if not(verbose):
                print ('URL:', j.getURL() )
             else:               
                print ('Description:', j.getDesc().encode('utf8').decode('utf8') )
                print ('Aliases:', j.getAliases() )
             return   

def GENERATE_MITIGATIONS (dataset, stats, mode):
    
   ret = sortByEntrypointSuccesses(stats)
   if ret:
      print ('\nTop 10 most successful entrypoints:')
      count = 0
      for j in ret:
          showNode(dataset, j)
          count = count + 1
          if count > 10:
              break
    
   ret = sortByVisitedNode (stats)
   if ret:
      print ('\nTop 10 most frequented IPs across all scenarios:')
      count = 0
      for j in ret:
            showNode (dataset, j)
            count = count + 1
            if count > 10:
                break
    
   ret = sortByTTPUsage(stats)
   if ret:
       print ('\nTop 10 most used ATT&CK TTPs:')
       count = 0
       for j in ret:
           showTechnique(dataset, j)
           showMitigation(dataset, j)
           count = count + 1
           if count > 10:
               break
           

def getTTP (dataset, ttpid):
   for j in dataset['ATT&CK']:
       if ttpid == j.getTECHID():
           return j
   for j in dataset['ATK4ICS TTPs']:
       if ttpid == j.getTECHID():
           return j       
   return None    

def SCENARIO_REPORT(dataset, stats, flagslist):
    print ('\n>>> SCENARIO REPORT <<<')
    for entry in stats.keys():
        SCENARIO_ENTRY (dataset, stats[entry][0], flagslist)

def SCENARIO_ENTRY (dataset, entry, flagslist ):    
       print ('\nScenario:', entry['name'])
       if ('Details' in flagslist):
          showActor(dataset, entry['actor'], True)
       else:
          showActor(dataset, entry['actor'], False)           

       print ('\nScenario Target:', entry['target'], 'Intended Effect:', entry['effect'], 'Impact score:', str(entry['score']) )
       print ('\nATTACK PATH:', entry['path'])
       for ip in entry['path']:
           bTarget = False
           if ip == entry['target']:
               bTarget = True
           if ('Details' in flagslist):
              showNode (dataset, ip, bTarget, True )
           else:
              showNode (dataset, ip, bTarget, False )
       print ('\nATT&CK TTP sequences:')
       x = 0
       for ttpseq in entry['ttps']:
          print ('\nAsset:', entry['path'][x] + ':')
          x = x + 1
          for ttpid in ttpseq:
             ttpobj = getTTP (dataset, ttpid)
             if ttpobj:
                if ('Details' in flagslist):
                    showTechnique (ttpobj, False )
                else:
                    showTechnique (ttpobj, False )                    
                if ('Mitigations' in flagslist):
                    showMitigation( ttpobj  )
                if ('Forensics' in flagslist):
                    showDetection( ttpobj )


def getACTOR (dataset, groupID):
   for j in dataset['ATKGROUPS']:
       if groupID == j.getGroupID():
           return j
       
def getIDs ( objlist ):
    ret = []
    for x in objlist:
        if x.typex == 'attack-pattern':
            ret.append (x.getTECHID() )
        elif x.typex =='malware':
            ret.append (x.getSID() )
        elif x.typex == 'tool':
            ret.append (x.getSID() )
        
    return ret
            
    
           
def ACTOR_REPORT (dataset, tactlist):  
    print ('\nACTOR REPORT')
    alist = sortActorsBySophistication(dataset)    
    rank = 1    
    for actorID in alist:
       print ('\nThreat Actor:', actorID, 'Rank:', str(rank), 'in list of', str(len(alist)) )
       showActor (dataset, actorID, True  )
       mlist = getCAPABILITIES (dataset, actorID, ['MALWARE'] )
       if mlist:
          print ('MALWARE:', mlist)
       
       tlist = getCAPABILITIES (dataset, actorID, ['TOOL'] )
       if tlist:    
          print ('TOOLS:', tlist)
          
       plist = getCAPABILITIES (dataset, actorID, ['TTP'] ) 
       if plist:
          print ('TTPs:', plist )
          TTP_DISTRIBUTION (dataset, tactlist, actorID) 
          
       rank = rank + 1
              

tactlist = ['initial-access', 'discovery', 'credential-access', 'privilege-escalation',
            'execution', 'collection', 'exfiltration', 'lateral-movement', 'command-and-control', 
            'persistence', 'defense-evasion' ]


def TTP_DISTRIBUTION (dataset, xxx, actorID):
    for t in tactlist:
        ttpcount = countTTPsByTactic (dataset, t, actorID )
        if ttpcount > 0:
           print ('Tactic:', t, 'Attributed TTPs:', ttpcount)

    return

def getCAPABILITIES (dataset, actorID, caplist):
    actOBJ = getACTOR (dataset, actorID)
    ret = []
    if actOBJ:
        for cap in caplist:
            if cap == 'TTP':
                ret.append(getIDs (actOBJ.getTTPList() ))
            elif cap == 'MALWARE':
                ret.append(getIDs (actOBJ.getMalwareList()))     
            elif cap == 'TOOL':
                ret.append( getIDs( actOBJ.getToolsList() )  )   
    return ret[0]
    
    
    
    
