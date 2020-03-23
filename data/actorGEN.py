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

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import sys
from ffactory import FILTER_FACTORY, INIT_FILTERS, getTTPs, showTTPs
from loaddata import LOAD_DATA, LOAD_TTP_SUPPLEMENT 
from topology import INIT_TOPOLOGY
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS, m_file_ODNI #m_file_EXTENSIONS
from TACSequence import m_TACTIC_LIST, initPatternMenu, m_objdict

from stats import TAGS_INDEX, x_TACTICS 

from mitGEN import ACTOR_REPORT
from ODNI import loadODNI, mapTTPs, augmentTTPs


# verifies the combination: threat actor, tactic, platform includes at least one TTP  
def checkCombo (factory, dataset, tactic, platform, actor, trace):
    ret = getTTPs(ffactory, dataset, tactic, platform, actor)       
    if trace:
       showTTPs ('FILTER TEST: ' + tactic + ', ' + platform + ', ' + actor +': ', ret )                
    return ret


# verifies tactic and platform combinations for a specified objctive sequence    
def verifyObjSequence (factory, dataset, seqname, platform, actor, trace):    

    ret = True
    entry = m_objdict[seqname][0]
    tIndexList = entry[1]
    
    if trace:
        print ('Verifying use of', seqname, 'by threat actor', actor, 'on', platform)

    for tIndex in tIndexList:
        tactic =  m_TACTIC_LIST[tIndex]
        if not (checkCombo (factory, dataset, tactic, platform, actor, False) ):
            ret = False
            if trace:
                print ('WARNING! threat actor', actor, 'has no TTPs for', tactic, 'on', platform )

    return ret

# verifies TTP usage for range of threat actors
def TestActorCapabilities(factory, dataset):
    
    actorlist = ['G0093', 'G0074', 'G0061', 'G0049', 'G0045', 'G0032', 'G0027', 'G0022', 'G0010', 'G0007'  ]
    seqlist = m_objdict.keys()
    platlist = ['Windows', 'Linux', 'macOS']
    
    for a in actorlist:
        print ('\n')
        print('Verifying TTPs for threat actor', a)
        for s in seqlist:
            for p in platlist:   
                verifyObjSequence (factory, dataset, s, p, a, True)
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
    zonemap = INIT_TOPOLOGY(myDATASET, True ) 
    loadODNI(m_file_ODNI )
    m_STAGES = mapTTPs(myDATASET['ATT&CK']) 
   
    LOAD_TTP_SUPPLEMENT (myDATASET) 
   
    denyTTPs = []
    for t in myDATASET['TTP_SUP']:
       if ['deny' in t.getTactic() ]:
           denyTTPs.append(t)          
    
    augmentTTPs('deny', denyTTPs)   
   
  
    ffactory = FILTER_FACTORY(False )
    INIT_FILTERS (ffactory, myDATASET)
        
    initPatternMenu()
    
    TAGS_INDEX (myDATASET, True)
    ACTOR_REPORT (myDATASET, x_TACTICS.keys() )     
    
    TestActorCapabilities(ffactory, myDATASET)
    
    
    print ('End of run')  

