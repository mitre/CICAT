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
TTPfilter.py - Main TTP filtering routine
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import sys
from loaddata import LOAD_DATA, m_file_TESTBED_MODEL, m_file_TESTBED_SCNRO  
from loaddata import m_filter_test_list, m_test_actor_list
from ffactory import FILTER_FACTORY, INIT_FILTERS, getTTPs, getTTPsforCTYPE, m_TACTIC_LIST

# ATT&CK tactics list
#m_TACTIC_LIST = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 
#               'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 
#                'impact', 'inhibit-response-function', 'impair-process-control' ]


def TTP_FILTER (dataset, ffactory, IPorHostame, pattern, platFlag, actor, actFlag, trace):

    for component in dataset['COMPONENT']:
        if component.getIPAddress() == IPorHostame:
            break

    if not (component):
        if trace:
            print ('WARNING TTP_FILTER: Component', IPorHostame, 'not found.')
        return    

    ctype = component.getCtype()
    if not (ctype):
       if trace:
           print ('WARNING TTP_FILTER: CTYPE for', IPorHostame, 'not found.')
       return
    
#   if platFlag use platform Filter (Windows, LInux) instead of surface Filter
         
    platform = None
    surflist = ctype.getSurfaceList()    
    if not (surflist):
        platform = ctype.getPlatform()
                                   
    actr = ''
    if actFlag:
        actr = actor.getGroupID()
               
    stepTTPs = getTTPs(ffactory, dataset, pattern, platform, actr)
   
    surfTTPs = []
    if surflist:
        surfTTPs = getTTPsforCTYPE(ffactory, dataset, ctype.getID() )
        
    ret = []
    for t in stepTTPs:
        ret.append (t.getTECHID())
        
    surfret = []
    if surfTTPs:
        for k in surfTTPs:
            surfret.append (k.getTECHID())
        
    retset = set(ret)
    if (surfret):
       retset = retset & set(surfret)
    
    ret = list(retset)
    
    if trace:
        if platform:
           print ('TTP_FILTER: Asset:', IPorHostame, 'Platform:', platform, 'Tactic:', pattern, 'TTPs:', ret )                     
        elif surflist:
           slist = []
           for s in surflist:
               slist.append (s.getSurface() )
               
           print ('TTP_FILTER: Asset:', IPorHostame, 'Surfaces:', slist, 'Pattern:', pattern, 'TTPs:', ret)
                     
        else:
           print ('Warning! TTP_FILTER:', IPorHostame, 'has no platform or surface list.')        
    
    return ret


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
#    LOAD_TTP_SUPPLEMENT(myDATASET)

    ffactory = FILTER_FACTORY(False )
    INIT_FILTERS (ffactory, myDATASET)
    
    testhosts = m_filter_test_list 
 
    print ('\n')
    print (' >>> Platform and Attack Surface Filter Test <<<' )
    
    for c in testhosts:
       for component in myDATASET['COMPONENT']:
         if component.getIPAddress() == c:
            component.PP(True)
            break  
        
       if not component.getSurfaceList():              
          print ('\n') 
          print ('Testing platform filter:', component.getPlatform() )
          for p in m_TACTIC_LIST:   
              ttpseq1 = TTP_FILTER (myDATASET, ffactory, c, p, True, None, False, False)
              print ('TTPs for', c, 'tactic:', p, '('+ str(len(ttpseq1)) + '):', ttpseq1)
       else:        
          print ('\n') 
          print ('Testing attack surface filter:', component.getCTYPEID() )
          for p in m_TACTIC_LIST:   
              ttpseq1 = TTP_FILTER (myDATASET, ffactory, c, p, False, None, False, False)
              print ('TTPs for', c, 'tactic:', p, '('+ str(len(ttpseq1)) + '):', ttpseq1)
           
            
    print ('\n')
    print (' >>> Threat Actor Filter Testing <<<' )

    actorlist = m_test_actor_list 
    
    for c in testhosts:        
       for component in myDATASET['COMPONENT']:
             if component.getIPAddress() == c:
                component.PP(True)
                break                     
        
       for a in actorlist:          
         for actor in myDATASET['ATKGROUPS']:
           if actor.getGroupID() == a:
              break
         
         if not component.getSurfaceList():      
            print ('\n') 
            print ('Testing platform filter:', component.getPlatform(), 'with actor', actor.getName() )
            for p in m_TACTIC_LIST:
              ttpseq2 = TTP_FILTER (myDATASET, ffactory, c, p, True, actor, True, False )
              print ('TTPs for', c, 'tactic:', p, '('+ str(len(ttpseq2)) + '):', ttpseq2 )
         else:        
            print ('\n') 
            print ('Testing attack surface filter:', component.getCTYPEID(), 'with actor', actor.getName() )
            for p in m_TACTIC_LIST:  
              ttpseq2 = TTP_FILTER (myDATASET, ffactory, c, p, False, actor, True, False )
              print ('TTPs for', c, 'tactic:', p, '('+ str(len(ttpseq2)) + '):', ttpseq2 )    

    print ('End of run')
    
    