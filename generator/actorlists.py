# -*- coding: utf-8 -*-
"""
Created on Tue Mar 17 11:02:58 2020

@author: JWYNN
"""

#import sys, time
from collections import defaultdict
from loaddata import LOAD_DATA, LOAD_ATK4ICS
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS #, m_file_EXTENSIONS, m_file_ODNI
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
        
    