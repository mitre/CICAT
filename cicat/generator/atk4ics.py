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
atk4ics.py - Utility to convert ATK4ICS XML file to spreadsheet that can be imported by CICAT
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


import xml.sax
import collections
from openpyxl import Workbook

from atk2xl import saveICSDataset

class ICSTTP():
   def __init__ (self, aid, techID):                     
          self.aid = aid
          self.techID = techID
          self.name = ''
          self.tactic = ''
          self.desc = ''
          self.platform = ''
          self.contributor = ''
          self.datasources = ''
          self.levels = ''
          self.mitigation = ''
          self.assets = ''
          self.url = ''
          
   def setName(self, name):
       self.name = name
       
   def setTactic (self, category):
       self.tactic = category
       
   def setDesc (self, desc):
       self.desc = desc
       
   def setPlatform (self, assets):
       self.platform = assets
       
   def setContributor(self, contributor):
       self.contributor = contributor
       
   def setDatasources (self, datasources):
       self.datasources = datasources
       
   def setLevels (self, levels):
       self.levels = levels
       
   def setMitigation (self, mitigation):
       self.mitigation = mitigation
       
   def setAssets (self, assets):
       self.assets = assets
       
   def getTECHID(self):
       return self.techID
       
   def setURL (self, urlstr):
       self.url = urlstr
       
   def PP(self):
       print ('\n')
       print (self.techID, ':', self.name)
       print (self.desc.encode('utf-8'))
       print ('Tactics:', self.tactic )
       print ('Levels:', self.levels )
       print ('Assets:', self.assets )
       print ('Platforms:', self.platform )
       print ('Sources:', self.datasources )
       print ('Mitigations:', self.mitigation.encode('utf-8') )
       print ('URL:', self.url)
      

m_urlbase = 'https://collaborate.mitre.org/attackics/index.php/Technique'

m_ICSlist = collections.defaultdict(list)

m_ignorelist = ['Permissions Required', 'Asset Specific Descriptions', 'Asset Specific Description', 'Free_Text']


class ICSHandler (xml.sax.ContentHandler):
    def __init__(self):
        self.currTag = ''
        self.currICS = None
        self.skipflag = False
        self.attributes = None
        self.fieldbuf = ''        
        
    def checkAttributes (self, attributes, trace):
        ret = False
        names = attributes.getNames()
        if 'ID' in names:
           if trace:
              print ('\nParsing:', attributes.getValue('Title') )
           ret = True
        elif len(names) == 1:
           if attributes.getValue(names[0]) in m_ignorelist:
             if trace:
                print ('...ignoring', attributes.getValue(names[0]) )
             self.skipflag = True 
           else:
             if trace:
                print ('Attribute:', attributes.getValue(names[0]))
             self.skipflag = False
             self.currTag = attributes.getValue(names[0])
        else:
          if trace:
             print ('empty attribute list..')  

        return ret             
                      
    def startElement(self, tag, attributes):
        self.skipflag = False
        if self.checkAttributes (attributes, False ):
            self.currID = attributes['ID']
            techID = attributes['Title'].split('/')[1]
            self.currICS = ICSTTP( self.currID, techID )
            m_ICSlist[self.currID] = self.currICS 
                   
    def endElement(self, tag):
        buf = self.fieldbuf.rstrip() 
        self.fieldbuf = buf
        if tag == 'Field':
#           print ('Field value:', self.fieldbuf.lstrip()
            if self.currTag == 'Technical Description':
                self.currICS.setDesc(self.fieldbuf.lstrip() )
            elif self.currTag == 'Name':
                self.currICS.setName(self.fieldbuf.lstrip() )
            elif self.currTag == 'Category':
                self.currICS.setTactic(self.fieldbuf.lstrip().split(', ' ))
            elif self.currTag == 'Data Sources':
                self.currICS.setDatasources(list(self.fieldbuf.lstrip().split(', ')) )
            elif self.currTag == 'Levels':
                self.currICS.setLevels(self.fieldbuf.lstrip().split(',') )
            elif self.currTag == 'Platform':
                self.currICS.setPlatform (self.fieldbuf.lstrip().split(', ') )
            elif self.currTag == 'Assets':
                tmp = self.fieldbuf.lstrip().replace(',', '/')
                self.currICS.setAssets (tmp.split('/' ) )
            elif self.currTag == 'Contributors':
                self.currICS.setContributor(self.fieldbuf.lstrip() )
            elif self.currTag == 'Mitigation':
                self.currICS.setMitigation (self.fieldbuf.lstrip() )
            self.fieldbuf = ''
            self.currTag = ''

        if self.skipflag:
            self.skipflag = False
            
    def characters(self, content):
      self.fieldbuf = self.fieldbuf + content
         

class ICSFactory(): 
    def __init__ (self, trace):
       self.file = ''
       self.trace = trace
       if self.trace:
           print ('ICSTTP factory constructed..')
             

    def load (self, xmlfile ):
       self.file = xmlfile
       parser = xml.sax.make_parser()
       parser.setFeature(xml.sax.handler.feature_namespaces, 0)
       Handler = ICSHandler()
       parser.setContentHandler( Handler )

       if self.trace:
          print ('Loading ICSTTP data..')

       parser.parse(self.file)
       
       if self.trace:
          print ("ICS data loaded:", len(m_ICSlist), "entries")        
 

def DumpICSToSpreadsheet(fname, m_ICSlist ):
    
    tablist = ['ATK4ICS TTPs', 'ATK4ICS MITs']   
    
    wb = Workbook()     
    for sheet in tablist:
        saveICSDataset (wb, sheet, m_ICSlist )              
    wb.save(filename = fname )    


# main entry point
if ( __name__ == "__main__"):
    

    infile = '..\\data\\atk4ics.xml'    
    outfile = '..\\data\ATK4ICS.xlsx'
    
    icsreader = ICSFactory (False )
    icsreader.load (infile )
    
# update entries to include URLs to ATK4ICS pages
    
    for i in m_ICSlist.keys():
        m_ICSlist[i].setURL (m_urlbase +'/'+ m_ICSlist[i].getTECHID() )
                
    print ('\n')
    print ('Creating', outfile)
    
    DumpICSToSpreadsheet (outfile, m_ICSlist )
 
    print('End of run')
    
