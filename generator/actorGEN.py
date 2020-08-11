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

The Government retains a nonexclusive, royalty-free right to publish  or reproduce this document, or to allow others to do so, for 
“Government Purposes Only.”                                           
                                            
(c) 2020 The MITRE Corporation. All Rights Reserved.

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
actorGEN.py - verifies threat actor capabilities over range of tactics and platforms
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import sys
from ffactory import FILTER_FACTORY, INIT_FILTERS, getTTPs, showTTPs
from loaddata import LOAD_DATA
from topology import INIT_TOPOLOGY
from loaddata import m_file_TESTBED_MODEL, m_file_TESTBED_SCNRO  #testbed data used for unit tests
from TACSequence import m_TACTIC_LIST, initPatternMenu, m_objdict
from stats import TAGS_INDEX, x_TACTICS 
from mitGEN import ACTOR_REPORT



# verifies the combination: threat actor, tactic, platform includes at least one TTP  
def filterTest (factory, dataset, tactic, platform, actor, trace):
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
        print ('\nVerifying use of', seqname, 'by threat actor', actor, 'on', platform)

    for tIndex in tIndexList:
        tactic =  m_TACTIC_LIST[tIndex]
        if not (filterTest (factory, dataset, tactic, platform, actor, trace) ):
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
    
    Ispread = m_file_TESTBED_MODEL
    Tspread = m_file_TESTBED_SCNRO 
 
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
  
    ffactory = FILTER_FACTORY(False )
    INIT_FILTERS (ffactory, myDATASET)
        
    initPatternMenu()
    
    TAGS_INDEX (myDATASET, True)
    ACTOR_REPORT (myDATASET, x_TACTICS.keys() )     
    
    TestActorCapabilities(ffactory, myDATASET)
    
    
    print ('End of run')  

