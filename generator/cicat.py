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

cicat.py - Critical Infrastructure Cyber Analysis Tool

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import sys, time
from collections import defaultdict
from loaddata import LOAD_DATA
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS, m_file_EXTENSIONS, m_file_ODNI

myDATAWARE = None

x_TACTICS = defaultdict(list)
x_PLATFORMS = defaultdict(list)
x_TYPES = defaultdict(list)

x_ACTTAGS = defaultdict(list)
x_TTPTAGS = defaultdict(list)
x_MALTAGS = defaultdict(list)
x_COATAGS = defaultdict(list)
x_TOLTAGS = defaultdict(list)


def printREPORT (title, lList, verbose=False ):
    print (title )
    for l in lList:
        print ('\n')
        l.PP(verbose)       
    print ('\n>>>   END OF REPORT    <<<')

def shortlist(listx, num):
    nxt = 0
    for entry in listx:
        entry.PP()
        nxt = nxt + 1
        if (nxt >= num):
            break

def checkForMods (ATTLIST, tstTime ):

    ret = []    
    for x in ATTLIST:
      try:
       if x.modifiedSince (tstTime):
           ret.append (x)
      except ValueError:
        print ('Time check error for', x.getName(), ':', x.modified )
      
      return ret

 
        
def Timecheck (tsttime, dataset):

   print ('Checking for updates since', tsttime )

   c1 = checkForMods (dataset['ATT&CK'], tsttime )
   if not (c1):
       print ('No changes to TTPs')
   else:
       print ('Changes to TTPs:', len(c1))

   c2 = checkForMods (dataset['ATKGROUPS'], tsttime )
   if not (c2):
       print ('No changes to Intrustion sets')
   else:
       print ('Changes to Intrustion sets:', len(c2))

   c3 = checkForMods (dataset['ATKMALWARE'], tsttime )
   if not (c3):
       print ('No changes to Malware')
   else:
       print ('Changes to Malware:', len(c3))

   c4 = checkForMods (dataset['ATKTOOL'], tsttime )
   if not (c4):
       print ('No changes to Tools')
   else:
       print ('Changes to Tools:', len(c4))    
       
   c5 = checkForMods (dataset['ATKMITIGATION'], tsttime )
   if not (c5):
       print ('No changes to Mitigations')
   else:
       print ('Changes to Mitigations:', len(c5))   


# main entry point
if ( __name__ == "__main__"):

    mode = 'CAPABILITY'
    params = sys.argv
    if (len(params) > 1 ):
        mode = params[1]
        
    if mode.lower() == 'help':
       print ('\nUSAGE: python', params[0], '[HELP|SCENARIO|CAPABILITY|LOCATION|ACTOR]')
       exit()  
       
    myDATAWARE = LOAD_DATA(m_file_INFRASTRUCTURE, m_file_SCENARIOS, True, False )
       
    for q in myDATAWARE['ATKGROUPS']:
       for j in q.getTags():
          x_ACTTAGS[j].append(q)
                 
    for q in myDATAWARE['ATKMALWARE']:
       for j in q.getTags():
          x_MALTAGS[j].append(q)

    for q in myDATAWARE['ATT&CK']:
       for j in q.getTags():
          x_TTPTAGS[j].append(q)
          
    for q in myDATAWARE['ATKMITIGATION']:
       for j in q.getTags():
          x_COATAGS[j].append(q)
          
    for q in myDATAWARE['ATKTOOL']:
       for j in q.getTags():
          x_TOLTAGS[j].append(q)                 
             
    testdates = [ (2018, 11, 15, 12, 34, 56, 0, 0, 0) ]  
    for dt in testdates:
       t = time.mktime(dt)
       ttm = time.strftime( "%Y-%m-%d %H:%M:%S", time.gmtime(t)) 
       print ('\nTimecheck:', ttm) 
       Timecheck (ttm, myDATAWARE)

    ttm = time.strftime( "%Y-%m-%d %H:%M:%S", time.localtime()) 
    print ('\nTimecheck:', ttm) 
    Timecheck (ttm, myDATAWARE)

    if (mode.lower() == 'scenario'):
       printREPORT('\n\n\n>>>   SCENARIO REPORT    <<<<', myDATAWARE['SCENARIOX'], True )  
    elif (mode.lower() == 'capability'):
       printREPORT('\n\n\n>>>   CAPABILITY REPORT    <<<<', myDATAWARE['CAPABILITY'], True )  
    elif (mode.lower() == 'location'):
       printREPORT('\n\n\n>>>   LOCATION REPORT    <<<<', myDATAWARE['LOCATION'], True )    
    elif (mode.lower() == 'actor'):
       printREPORT('\n\n\n>>>   ACTOR REPORT    <<<<', myDATAWARE['ACTOR'], True )            
    else:
       print ('\nUSAGE: python cicat.py [SCENARIO|CAPABILITY|LOCATION|ACTOR]')

      

print ("end of run")
