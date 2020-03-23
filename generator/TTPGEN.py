# -*- coding: utf-8 -*-
"""
Created on Tue Feb 18 14:29:19 2020

@author: JWYNN
"""

import sys
from collections import defaultdict
from loaddata import LOAD_DATA, LOAD_TTP_SUPPLEMENT
from ffactory import FILTER_FACTORY, INIT_FILTERS, getTTPs, getTTPsforCTYPE, FILTER_TEST
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS


m_testsys = ['DCAE1TSC001', 'NAIMES_EDMZ_2'] 

m_testpatt  = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 
               'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'deny' ] #impact TBD

def showTTPs (title, ttplist): 
    print (title, '(' + str(len(ttplist)), 'entries)', ttplist)    


def TTP_FILTER (dataset, IPorHostame, pattern, platFlag, actor, actFlag, trace):

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
    surflist = None
    
    if platFlag:
       platform = ctype.getPlatform()
       if trace:
           print ('INFO TTP_FILTER: CTYPE for', IPorHostame, 'platform set to:', platform )
    else:        
       surflist = ctype.getSurfaceList()
       if surflist:
           if trace:
               print('INFO TTP_FILTER: CTYPE for', IPorHostame, 'includes surface list:', surflist)
            
    if not(platform) and not(surflist):
        if trace:
            print ('INFO TTP_FILTER: CTYPE for', IPorHostame, 'no platform or surface list.')
            
    actr = ''
    if actFlag:
        actr = actor.getGroupID()
        if trace:
            print ('INFO TTP_FILTER: Actor set to', actr)
               
    stepTTPs = getTTPs(ffactory, dataset, pattern, platform, actr)
    if trace:
       title = 'getTTPs', pattern, platform, actr
       showTTPs(title, stepTTPs)
    
    surfTTPs = []
    if surflist:
        surfTTPs = getTTPsforCTYPE(ffactory, dataset, ctype.getID() )
        if trace:
           title = 'getTTPsforCTYPE', ctype.getID() 
           showTTPs(title, surfTTPs)       
        
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
    
    return list(retset)


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
    LOAD_TTP_SUPPLEMENT(myDATASET)
       
    ffactory = FILTER_FACTORY(False )
    INIT_FILTERS (ffactory, myDATASET)
 
    print ('\n')
    print (' >>> Attack Surface Filter Test <<<' )
    
    for c in m_testsys:
       for component in myDATASET['COMPONENT']:
         if component.getIPAddress() == c:
            component.PP(True)
            break  
              
       print ('\n') 
       print ('Platform Test')
       for p in m_testpatt:   
           ttpseq1 = TTP_FILTER (myDATASET, c, p, True, None, False, False)
           showTTPs ('\nATT&CK_PICS for ' + c + ' (' + component.getPlatform() + ', ' + 'XXXXX' + ') ' + p + ': ', ttpseq1)


    for c in m_testsys:
       for component in myDATASET['COMPONENT']:
         if component.getIPAddress() == c:
            component.PP(True)
            break                
       
       print ('\n') 
       print ('Attack Surface Test')
       for p in m_testpatt:   
           ttpseq1 = TTP_FILTER (myDATASET, c, p, False, None, False, False)
           showTTPs ('\nATT&CK_PICS for ' + c + ' (' + 'XXXXX' + ', ' + component.getCTYPEID() + ') ' + p + ': ', ttpseq1)
           
    print ('\n')
    print (' >>> Attack Surface + Actor Filter Test <<<' )

    actorlist = ['G0007', 'G0006', 'G0050', 'G0053', 'G0041']
    
    for c in m_testsys:
      for a in actorlist:          
         for actor in myDATASET['ATKGROUPS']:
           if actor.getGroupID() == a:
              break
    
         for c in m_testsys:
             for component in myDATASET['COMPONENT']:
               if component.getIPAddress() == c:
                  component.PP(True)
                  break                
 
             print ('\n') 
             print ('Platform Test')       
             for p in m_testpatt:   
                 ttpseq2 = TTP_FILTER (myDATASET, c, p, True, actor, True, False )
                 showTTPs ('\nATT&CK_PICS for ' + c + ' (' + component.getPlatform() + ', ' + 'XXXXX' + ') ' + p + ' ' + actor.getGroupID() + ' [' + actor.getName() + '] ' + ': ', ttpseq2)
           
             print ('\n') 
             print ('Attack Surface Test')       
             for p in m_testpatt:   
                 ttpseq2 = TTP_FILTER (myDATASET, c, p, False, actor, True, False )
                 showTTPs ('\nATT&CK_PICS for ' + c + ' (' + 'XXXXX' + ', ' + component.getCTYPEID() + ') ' + p + ' ' + actor.getGroupID() + ' [' + actor.getName() + '] ' + ': ', ttpseq2)        
 

    print ('End of run')