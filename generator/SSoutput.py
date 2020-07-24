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
SSoutput.py - Routines to generate scenario spreadsheet output
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

from openpyxl import Workbook

m_taginfo = {'Scenario' : [1, 1], 
             'Scenario Desc' : [2, 1], 
             'Entry Point' : [3,1 ],
             'Threat Actor' : [5, 1], 
             'Sophistication' : [6, 1], 
             'Tactics Pattern' : [7, 1], 
             'Target' : [9, 1], 
             'Impact score [0...160]' : [10, 1], 
             '1st order effects' : [11, 1], 
             '2nd order effects' : [12, 1], 
             '3rd order effects' : [13, 1], 
             'Attack Path Component' : [15, 1], 
             'Description' : [16, 1], 
             'Platform' : [17, 1], 
             'System' : [18, 1], 
             'Techniques' : [20, 1], 
             'Mitigations' : [30, 1], 
             'Forensics' : [40, 1], 
             'Vendor Product Vulnerabilities' : [46, 1] }

def list2string(plist, separator):
    ret = 'undefined'
    if plist:
       ret = str(plist[0])
       for j in range (1, len(plist)):
           ret = ret + separator + str(plist[j])
    return ret

def getTTPlist (tracedata):
    ttplist = []
    for k in tracedata.keys():
        curdict = tracedata[k]
        curtrace = curdict[0]
        tlist = curtrace['ttps']   
        for x in tlist:
           if len(x) > 0:
               for xx in x:
                  ttplist.append(xx)

    tset = set (ttplist)  # dump list into set to elimnate duplicates
    ret = list (tset)     # dump back into  list

    return ret

def getMITsforTTP (dataset, ttpID ):
    for t in dataset['ATT&CK']:
        ret = []
        if t.getTECHID() == ttpID:
            clist = t.getCOA()
            for c in clist:
               ret.append(c[0].getTECHID() )
            return ret
 

def getMITsforTTPList (dataset, ttplist):
    clist = []
    for x in ttplist:
        clist = clist + getMITsforTTP(dataset, x)

    uset = set (clist)
    ret = list (uset)
    
    return ret

def getFromToList(path):
    ret = []
    idx = 0
    while idx < len(path)-1 :
        ret.append([path[idx], path[idx+1]])
        idx = idx + 1
    
    return ret

def writeField (sheet, tag, value=None, rowval=-1):
    row, col = m_taginfo[tag]
    if rowval > 0:
        row = rowval
    sheet.cell (row, col, tag+':')
    if value:
       sheet.cell (row, col+1, value)
    
def writeBlockData (sheet, row, col, listdata ):
    idx = 0
    for k in listdata:
        sheet.cell (row+idx, col, k)
        idx = idx + 1       
    return idx
 
def writeRowData (sheet, tag, pathinfo):
    row, col = m_taginfo[tag]  
    sheet.cell (row, col, tag+':') 
    for c in pathinfo:
        col = col + 1
        sheet.cell (row, col, c)
        
def getComponentInfo(dataset, cname):
    ret = []
    for c in dataset['COMPONENT']:
        if c.getName() == cname:
           cdet = c.getVendor() + ' ' + str(c.getDesc())
           ret.append (cdet)
           ret.append (c.getPlatform() )
           ret.append (c.getSysName() )
           return ret
       
        
def updateEffects (dataset, sheet, cname):
    for c in dataset['COMPONENT']:
        if c.getName() == cname:          
            writeField (sheet, '1st order effects', c.getSystemAffected() )
            writeField (sheet, '2nd order effects', list2string (c.getFunctionsAffected(), ', ') )
            writeField (sheet, '3rd order effects', list2string (c.getCapabilitiesAffected(), ', ') )

def getActorSophistication (dataset, actorName):
   for a in dataset['ATKGROUPS']:  
       if a.getName() == actorName:
           return a.getSophisticationLevel()

def writeComponentDetails (dataset, sheet, atkpath):
    cdesc = []
    cplat = []
    sname = []
    
    for x in atkpath:
        cinfo = getComponentInfo (dataset, x)
        cdesc.append (cinfo[0])
        cplat.append (cinfo[1])
        sname.append (cinfo[2])
        
    writeRowData (sheet, 'Description', cdesc)
    writeRowData (sheet, 'Platform', cplat )
    writeRowData (sheet, 'System', sname)


def getTechniqueInfo (dataset, techID):
    ret = []
    for t in dataset['ATT&CK']:
        if t.getTECHID() == techID:
            ret.append(t.getTECHID() + ' : ' + t.getName() )
            ret.append (list2string (t.getTactic(), ', '))
            ret.append (t.getURL() )
            return ret
    
    for i in dataset['ATK4ICS TTPs']:
        if i.getTECHID() == techID:
            ret.append (i.getTECHID() + ' : ' + i.getName() )
            ret.append (list2string(i.getTactic(), ', '))
            ret.append (i.getURL() )
            return ret
        
        
def getMitigationInfo (dataset, techID):
    ret = []
    for t in dataset['ATT&CK']:
        if t.getTECHID() == techID:
            mlist = t.getCOA()
            for m in mlist:
                mit = m[0]
                if (mit.getTECHID() == techID):  # ATT&CK portal gives 404 errors for old mitigations... Omit from list
                    continue
                ret.append (mit.getTECHID() + ' : ' + mit.getName() )
                ret.append (mit.getURL() )
                ret.append (" ")
            return ret
    
    for t in dataset['ATK4ICS TTPs']:
        if t.getTECHID() == techID:
            mlist = t.getCOA()
            for m in mlist:
                mit = m[0]
                ret.append (mit.getTECHID() + ' : ' + mit.getName() )
                ret.append (mit.getURL() )
                ret.append (" ")
            return ret
        
def getForensicInfo (dataset, techID):
    
    ret = []
    for t in dataset['ATT&CK']:
        if t.getTECHID() == techID:   
            ret.append(t.getDET() )
            return ret
    
    for t in dataset['ATK4ICS TTPs']:
        if t.getTECHID() == techID:
            ret.append (t.getDET() )
            return ret    
    
         
def writeTTPDetails (dataset, sheet, path, ttplist):

    writeField (sheet, 'Techniques')
    idx = 0
    maxrow = 0
    for p in path:
        tlist = ttplist[idx]
        tdetail = []
        for t in tlist:
            tinfo = getTechniqueInfo (dataset, t)
            if tinfo:
                tdetail.append(tinfo)

        row, col = m_taginfo['Techniques']  
        for d in tdetail:     
            row = row + writeBlockData (sheet, row, idx+2, d ) + 1
            if row > maxrow:
                maxrow = row
        idx = idx + 1
    
    return maxrow


def writeMITDetails (dataset, sheet, startrow, path, ttplist):
    
    writeField (sheet, 'Mitigations', rowval=startrow)
    
    idx = 0
    maxrow = 0
    for p in path:
        tlist = ttplist[idx]
        tdetail = []
        for t in tlist:
            tinfo = getMitigationInfo (dataset, t)
            if tinfo:
                tdetail.append(tinfo)

        row, col = m_taginfo['Mitigations'] 
        row = startrow
        for d in tdetail:     
            row = row + writeBlockData (sheet, row, idx+2, d ) + 1
            if row > maxrow:
                maxrow = row
        idx = idx + 1
    
    return maxrow    

def writeForensicInfo (dataset, sheet, startrow, path, ttplist):
    
    writeField (sheet, 'Forensics', rowval=startrow)
    
    idx = 0
    maxrow = 0
    for p in path:
        tlist = ttplist[idx]
        tdetail = []
        for t in tlist:
            tinfo = getForensicInfo (dataset, t)
            if tinfo:
                tdetail.append(tinfo)

        row, col = m_taginfo['Mitigations'] 
        row = startrow
        for d in tdetail:     
            row = row + writeBlockData (sheet, row, idx+2, d ) + 1
            if row > maxrow:
                maxrow = row
        idx = idx + 1
    
    return maxrow    
    
def getCVEInfo (vlist, maxcount):
    count = 0
    ret = []
    for v in vlist:
          ret.append('https://nvd.nist.gov/vuln/detail/'+ v.getCVE())
          count = count + 1
          if count > maxcount:
              break
    
    return ret
        
def writeCVEInfo (dataset, sheet, startrow, maxcount, path ):
    
    writeField (sheet, 'Vendor Product Vulnerabilities', rowval=startrow)
    
    idx = 1    
    for x in path: 
       idx = idx + 1
       vlist = []
       for c in dataset['COMPONENT']:
           if c.getName() == x:
               vlist = c.getVulnerabilityList()
               if vlist:
                   olist = getCVEInfo (vlist, maxcount)
                   row, col = m_taginfo['Vendor Product Vulnerabilities'] 
                   row = startrow
                   writeBlockData (sheet, row, idx, olist)
                   break
  
           
def DumpScenarioDetail (wb, key, tracedata, dataset):
    sheet = wb.create_sheet (title=key)    
    scendata = tracedata[key]
    scendatax = scendata[0]
    
    name = scendatax['name']    
    sname = name.split('EP')    
    writeField (sheet, 'Scenario', sname[0])
       
    for s in dataset['SCENARIO']:
        if s.getID() == sname[0]:
           writeField (sheet, 'Scenario Desc', s.getDesc() )
           
    writeField (sheet, 'Entry Point', sname[1])

    path = scendatax['path']
    writeRowData (sheet, 'Attack Path Component', path)
    
    writeComponentDetails (dataset, sheet, path)
    
    actor = scendatax['actor']
    writeField (sheet, 'Threat Actor', actor)    
    writeField (sheet, 'Sophistication', getActorSophistication (dataset, actor) )
    
    pattern = scendatax['effect']
    writeField (sheet, 'Tactics Pattern', pattern)
        
    target = scendatax['target']
    writeField (sheet, 'Target', target)    
        
    score = scendatax['score']
    writeField (sheet, 'Impact score [0...160]', score)
    
    updateEffects (dataset, sheet, target)
    
    ttplist = scendatax['ttps']
    maxrow = writeTTPDetails (dataset, sheet, path, ttplist)
    maxrow = writeMITDetails (dataset, sheet, maxrow, path, ttplist)
    maxrow = writeForensicInfo (dataset, sheet, maxrow, path, ttplist)
    writeCVEInfo (dataset, sheet, maxrow, 10, path )
    
    
               
def DumpScenario (fname, tracedata, dataset ):
    wb = Workbook() 
    for s in tracedata.keys():
        DumpScenarioDetail (wb, s, tracedata, dataset)
    wb.save(filename = fname )   
    
# main entry point
if ( __name__ == "__main__"):   
   print ('No unit test currently supported.')
    
    
    
    