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
loaddata.py - Master data loader
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

from collections import defaultdict
from afactory import ATTACK_FACTORY
from ifactory import CI_FACTORY
from tfactory import THREAT_FACTORY
from vfactory import VULNERABILIY_FACTORY
from stats import sortSystemsbyFunction
import os

m_CVEFiles = []
for cve in os.listdir(os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "CVE"))):
    m_CVEFiles.append(os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "CVE", cve)))

m_file_INFRASTRUCTURE = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "INFRASTRUCTURE.xlsx"))
m_file_SCENARIOS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "SCENARIOS.xlsx"))
m_file_OSPREAD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "OUTPUT.xlsx"))
m_file_ESPREAD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "EXPORT.xlsx"))

m_file_EXTENSIONS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "ATTACK_EXTENSIONS.xlsx"))
m_file_ODNI = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "ODNI.xlsx"))

m_file_ATK4ICS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "ATK4ICS.xlsx"))


def LOAD_DATA (infraSpread, threatSpread, CVEflag, trace):
    ret = defaultdict(list)
    
    CI_spreadsheet = infraSpread
    print('\nloaddata: Loading infrastructure data from', CI_spreadsheet)
    
    # load infrastructure model data from spreadsheet
    ciFACTORY = CI_FACTORY(CI_spreadsheet, trace)  
    ret['CAPABILITY'] = ciFACTORY.getLoader('CAPABILITY').load()
    ret['FUNCTION']  = ciFACTORY.getLoader('FUNCTION').load()
    ret['SYSTEM'] = ciFACTORY.getLoader('SYSTEM').load()
    ret['FSMAP'] = ciFACTORY.getLoader('FSMAP').load()
    ret['LOCATION'] = ciFACTORY.getLoader ('LOCATION').load()
    ret['CTYPE'] = ciFACTORY.getLoader('CTYPE').load()
    ret['COMPONENT'] = ciFACTORY.getLoader('COMPONENT').load(ret['CTYPE'])
    ret['SURFACE'] = ciFACTORY.getLoader('SURFACE').load()
    ret['CONNECTION'] = ciFACTORY.getLoader('CONNECTION').load()
          
    # if CVEflag, load CVE data from list of CVE files 
    
    if CVEflag:
       print('Loading CVE data from', m_CVEFiles)
       vlnFACTORY = VULNERABILIY_FACTORY(trace)
       ret['VULNERABILITY'] = vlnFACTORY.load(m_CVEFiles, ret['CTYPE'])

    # Initialize infrastructure relationships [requires vulnerability data be preloaded]
    ciFACTORY.initRelationships(ret )
    
    for c in ret['COMPONENT']:
        c.getAccessibility()
        c.getSusceptibility()

    # Initalize infrastructure criticality data
    for j in ret['FUNCTION']:
        j.assertCriticality(trace)
        
    for x in ret['SYSTEM']:
        x.assertCriticality(trace)   

    loadOpt = 'JSON' # 'STIX' 'SPREAD'
    loadFile = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'data', 'ATTACK.xlsx'))  
    if loadOpt == 'SPREAD':
      print('Loading ATT&CK data from spreadsheet', loadFile)
    elif loadOpt == 'JSON':
      print('Loading ATT&CK data from local JSON file') 
    elif loadOpt == 'STIX':
      print('Loading ATT&CK data from STIX//TAXII service')          
    
    # Load ATT&CK data from spreadsheet
    atkFACTORY = ATTACK_FACTORY(loadOpt, loadFile, trace)  
    ret['ATKGROUPS'] = atkFACTORY.loadGroups()
    ret['ATKMALWARE'] = atkFACTORY.loadMalwares()
    ret['ATT&CK'] = atkFACTORY.loadTechniques()
    ret['ATKMITIGATION'] = atkFACTORY.loadMitigations()
    ret['ATKTOOL'] = atkFACTORY.loadTools()
    ret['ATKRELS'] = atkFACTORY.initRelationships(ret)   
    
    
    # Load ATT&CK4ICS
    ret['ATK4ICS TTPs'] = atkFACTORY.loadTechniquesFromSheet (m_file_ATK4ICS, 'ATK4ICS TTPs')
    ret['ATK4ICS MITs'] = atkFACTORY.loadMitigationsFromSheet (m_file_ATK4ICS, 'ATK4ICS MITs')

    # link TTPs with associated MITs and vice versa
    for t in ret['ATK4ICS TTPs']:
        for m in ret['ATK4ICS MITs']:
            if t.getTECHID() == m.getTECHID():
                t.addCOA(m, None)
                m.addMitigates(t, None)
                break

    # Loading scerario spreadsheet data
    print('loaddata: Loading Scenario data from', threatSpread)

    # Load Threat Actor profiles                
    profilist = atkFACTORY.loadProfileNames(threatSpread)
    for p in profilist:    
       actor = atkFACTORY.loadGroupProfile (ret, threatSpread, p)
       ret['ATKGROUPS'].append (actor)

    # Calculated sophistication metric for each threat actor     
    for a in ret['ATKGROUPS']:
        a.getSophisticationLevel()
    
    trFACTORY = THREAT_FACTORY(threatSpread, trace)    
    ret['TARGET'] = trFACTORY.getLoader('TARGET').load()
    ret['ENTRYPOINT'] = trFACTORY.getLoader('ENTRYPOINT').load()
    ret['SCENARIO'] = trFACTORY.getLoader('SCENARIO').load() 

    # Load H800-53 controls
#    ret['COA'] = trFACTORY.getLoader('COA').load(os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'data', '800-53', 'controls.2.xlsx')))
   
    for t in ret['TARGET']:
        t.initTarget (ret['COMPONENT'])
        
    for e in ret['ENTRYPOINT']:
        e.initEntrypoint (ret['COMPONENT'])
        
    trFACTORY.initRelationships(ret)              

    return ret

def LOAD_TTP_EXTENSION (dataset, fname=m_file_EXTENSIONS, sheetname='TTP_EXT'):
    atkFACTORY = ATTACK_FACTORY('SPREAD', fname, False)  
    atkFACTORY.loadTTPExtension(dataset, fname, sheetname)

def LOAD_TTP_SUPPLEMENT (dataset, fname=m_file_EXTENSIONS, sheetname='TTP_SUP'):
    atkFACTORY = ATTACK_FACTORY('SPREAD', fname, False)
    dataset[sheetname] = atkFACTORY.loadTechniquesFromSheet(fname, sheetname)


# main entry point
if ( __name__ == "__main__"):
    
    mydataset = LOAD_DATA(m_file_INFRASTRUCTURE, m_file_SCENARIOS, False, True)
    sysdeplist = sortSystemsbyFunction(mydataset)
        
    print('End of run')
    
