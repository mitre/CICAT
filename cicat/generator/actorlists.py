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
actorlists.py - Generates actor profiles from imported ATT&CK and ATT&CK for ICS data     
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

#import sys, time
from collections import defaultdict
from loaddata import LOAD_DATA, LOAD_ATK4ICS
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS
from columnloader import DumpColsToSpreadsheet

def getMasterTTPlist (dataset):
    ret = []
    for x in dataset['ATT&CK']:
        ret.append (x.getTECHID())
        
    for i in dataset['ATK4ICS TTPs']:
        ret.append (i.getTECHID() )
        
    return ret
        

def getTTPidList (ttplist):
    ret = []
    for t in ttplist:
        ret.append(t.getTECHID())
        
    return ret

# main entry point
if ( __name__ == "__main__"):
       
    testfile = '..\\data\\ATKPROFILES.xlsx'
    myDATAWARE = LOAD_DATA(m_file_INFRASTRUCTURE, m_file_SCENARIOS, False, False )
    LOAD_ATK4ICS (myDATAWARE, '..\\data\ATK4ICS.xlsx' )
    
    atkdict = defaultdict(list)
    
    atkdict['MASTER'] = getMasterTTPlist(myDATAWARE)
       
    for j in myDATAWARE['ATKGROUPS']:
        atkdict[j.getGroupID()] = getTTPidList(j.getTTPList()) 
        
    DumpColsToSpreadsheet (testfile, 'ACTOR PROFILES', atkdict)
        
    