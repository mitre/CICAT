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


loaddata.py - Utility functions for importing data

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

from collections import defaultdict
from afactory import ATTACK_FACTORY
from ifactory import CI_FACTORY
from tfactory import THREAT_FACTORY
#from tmodel import ENTRYPOINT
from vfactory import VULNERABILIY_FACTORY
from stats import sortSystemsbyFunction
import os

m_CVEFiles = []
for cve in os.listdir(os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "CVE"))):
    m_CVEFiles.append(os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "CVE", cve)))

m_file_INFRASTRUCTURE = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "INFRASTRUCTURE.xlsx"))
m_file_SCENARIOS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "SCENARIOS.xlsx"))

m_file_EXTENSIONS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "ATTACK_EXTENSIONS.xlsx"))
m_file_ODNI = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "ODNI.xlsx"))

m_file_ATK4ICS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "ATK4ICS.xlsx"))


def LOAD_DATA (infraSpread, threatSpread, CVEflag, trace):
    ret = defaultdict(list)
    
    CI_spreadsheet = infraSpread
    print('\nLoading infrastructure data from', CI_spreadsheet)
    
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
                
    # Load Threat Actor profiles                
    profilist = atkFACTORY.loadProfileNames(m_file_SCENARIOS)
    for p in profilist:    
       actor = atkFACTORY.loadGroupProfile (ret, m_file_SCENARIOS, p)
       ret['ATKGROUPS'].append (actor)

    # Calculated sophistication metric for each threat actor     
    for a in ret['ATKGROUPS']:
        a.getSophisticationLevel()

    # Loading scerario spreadsheet data
    print('Loading Scenario data from', threatSpread)
    
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
    
#def LOAD_ATK4ICS (dataset, fname):
#    atkFactory = ATTACK_FACTORY ('SPREAD', fname, False)
#    dataset['ATK4ICS TTPs'] = atkFactory.loadTechniquesFromSheet (fname, 'ATK4ICS TTPs')
#    dataset['ATK4ICS MITs'] = atkFactory.loadMitigationsFromSheet (fname, 'ATK4ICS MITs')

    # link TTPs with associated MITs and vice versa
#    for t in dataset['ATK4ICS TTPs']:
#        for m in dataset['ATK4ICS MITs']:
#            if t.getTECHID() == m.getTECHID():
#                t.addCOA(m, None)
#                m.addMitigates(t, None)
#                break

                
#def LOAD_ACTOR_PROFILES (fname, dataset):
#    atkFactory = ATTACK_FACTORY ('NADA', fname, False)
#    profilist = atkFactory.loadProfileNames(fname)
#    for p in profilist:    
#       actor = atkFactory.loadGroupProfile (dataset, fname, p)
#       dataset['ATKGROUPS'].append (actor)


# main entry point
if ( __name__ == "__main__"):
    
    mydataset = LOAD_DATA(m_file_INFRASTRUCTURE, m_file_SCENARIOS, False, True)
    sysdeplist = sortSystemsbyFunction(mydataset)
#    LOAD_ATK4ICS (mydataset, '..\\data\ATK4ICS.xlsx' )
#    LOAD_ACTOR_PROFILES (m_file_SCENARIOS, mydataset )
        
    print('End of run')
    
