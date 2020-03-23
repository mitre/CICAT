# -*- coding: utf-8 -*-
"""
Created on Tue Feb 18 14:29:19 2020

@author: JWYNN
"""

import sys
from loaddata import LOAD_DATA, LOAD_TTP_SUPPLEMENT, LOAD_ATK4ICS, LOAD_ACTOR_PROFILES
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS
from ffactory import FILTER_FACTORY, INIT_FILTERS, getTTPs, getTTPsforCTYPE


# ATT&CK tactics list
m_TACTIC_LIST = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 
               'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', #'deny',
                'impact', 'inhibit-response-function', 'impair-process-control' ]



def TTP_FILTER (dataset, ffactory, IPorHostame, pattern, platFlag, actor, actFlag, trace):

    for component in dataset['COMPONENT']:
        if component.getIPAddress() == IPorHostame:
            break

    # assume all threat actors have deny TTPs
    if (pattern == 'deny'):
        actFlag = False
 
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
            
    if trace:
        print ('\n')
        if platform:
           print ('TTP_FILTER: CTYPE for', IPorHostame, 'platform set to:', platform )
        elif surflist:
           print ('TTP_FILTER: CTYPE for', IPorHostame, 'includes surface list:')
           for s in surflist:
              print('Surface:', s.getSurface() )
        else:
           print ('Warning! TTP_FILTER:', IPorHostame, 'has no platform or surface list.')    
                       
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
        print('TTP_FILTER() returns:', ret)
    
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
        
    Ispread = m_file_INFRASTRUCTURE
    Tspread = m_file_SCENARIOS
    
    testhosts = ['DCAE1TSC001', 'NAIMES_EDMZ_2', 'SiemensPLC_#3', 'SiemensPLC_#2'] 
 
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
    LOAD_ACTOR_PROFILES (Tspread, myDATASET, ['SCADACAT', 'ICSCUB_1', 'RedCanary', 'APT28', 'APT1', 'OilRig', 'Lazarus Group', 'Leviathan'] )
       
    ffactory = FILTER_FACTORY(False )
    INIT_FILTERS (ffactory, myDATASET)
 
    print ('\n')
    print (' >>> Platform and Attack Surface Filter Test <<<' )
    
    for c in testhosts:
       for component in myDATASET['COMPONENT']:
         if component.getIPAddress() == c:
            component.PP(True)
            break  
              
       print ('\n') 
       print ('Testing platform filter')
       for p in m_TACTIC_LIST:   
           ttpseq1 = TTP_FILTER (myDATASET, ffactory, c, p, True, None, False, False)
           print ('ATT&CK_PICS for ' + c + ' (' + component.getPlatform() + ', ' + 'XXXXX' + ') ' + p + ': ', ttpseq1)


    for c in testhosts:
       for component in myDATASET['COMPONENT']:
         if component.getIPAddress() == c:
            component.PP(True)
            break                
       
       print ('\n') 
       print ('Testing attack surface filter')
       for p in m_TACTIC_LIST:   
           ttpseq1 = TTP_FILTER (myDATASET, ffactory, c, p, False, None, False, False)
           print ('ATT&CK_PICS for ' + c + ' (' + 'XXXXX' + ', ' + component.getCTYPEID() + ') ' + p + ': ', ttpseq1)
           
    print ('\n')
    print (' >>> Threat Actor Filter Testing <<<' )

    actorlist = ['ICSCUB_1', 'RedCanary', 'APT28' ] #'G0007'] #, 'G0006', 'G0050', 'G0053', 'G0041']
    
    for c in testhosts:
      for a in actorlist:          
         for actor in myDATASET['ATKGROUPS']:
           if actor.getGroupID() == a:
              break
    
         for c in testhosts:
             for component in myDATASET['COMPONENT']:
               if component.getIPAddress() == c:
                  component.PP(True)
                  break                
 
             print ('\n') 
             print ('Testing platform filter with actor', actor.getName() )       
             for p in m_TACTIC_LIST:   
                 ttpseq2 = TTP_FILTER (myDATASET, ffactory, c, p, True, actor, True, False )
                 print ('ATT&CK_PICS for ' + c + ' (' + component.getPlatform() + ', ' + 'XXXXX' + ') ' + p + ':', ttpseq2)
           
             print ('\n') 
             print ('Testing attack surface filter with actor', actor.getName() )       
             for p in m_TACTIC_LIST:   
                 ttpseq2 = TTP_FILTER (myDATASET, ffactory, c, p, False, actor, True, False )
                 print ('ATT&CK_PICS for ' + c + ' (' + 'XXXXX' + ', ' + component.getCTYPEID() + ') ' + p + ':', ttpseq2)        
 

    print ('End of run')