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


vfactory.py - Factory class for loading CVE vulnerability data

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import xml.sax
import collections
import re

from tmodel import VULNERABILITY

m_CVElist = collections.defaultdict(list)

class CVEHandler (xml.sax.ContentHandler):
    def __init__(self):
        self.CurrentData = ""
        self.currCVE = ""
        self.skipflag = False
        
    def startElement(self, tag, attributes):
        self.CurrentData = tag
        if tag == "Vulnerability":
            self.currCVE = VULNERABILITY(attributes["Ordinal"])
        elif (( tag == "Note") and (attributes["Type"] == "Other")):
            self.skipflag = True
            
    def endElement(self, tag):
        if tag == "Vulnerability":
            m_CVElist[self.currCVE.getTitle()] = self.currCVE
        elif ((tag == "Note") and self.skipflag ):
            self.skipflag = False
            
    def characters(self, content):
      if self.currCVE == '':
          return
      elif self.CurrentData == "Title":
          if self.currCVE.getTitle() == '':
             self.currCVE.setTitle (content)
      elif ((self.CurrentData == "Note") and not(self.skipflag)):
          self.currCVE.setDescription(content )
      elif self.CurrentData == "URL":
          if (content.find('http') >= 0):
             self.currCVE.addReference (content )
          
def findCVEs( pattern):
    ret = []
    p = re.compile(pattern, re.IGNORECASE)
    for j in m_CVElist:
        entry = m_CVElist.get(j)
        if p.search(entry.getDescription().casefold() ):
            ret.append(j)
    return ret

def CVEsetbyVendor(vendor):
    ret = set()
    vlst = findCVEs(vendor)
    for v in vlst:
        ret.add(v)  
    return ret

def CVEsetbyType (eqtype):
    ret = set()
    vlst = findCVEs(eqtype)
    for v in vlst:
        ret.add (v)
    return ret

def CVEsetbyModel (modelinfo):
    ret = set()
    vlst = findCVEs(modelinfo)
    for v in vlst:
        ret.add(v)
    return ret


def showCVE(name):
    m_CVElist[name].PP()
        

class VULNERABILIY_FACTORY(): 
    def __init__ (self, trace):
       self.filelist = []
       self.trace = trace
       if self.trace:
           print ('VULNERABILITY factory constructed..')
             
    def load (self, filelist, ctypelist ):
       self.filelist = filelist
       parser = xml.sax.make_parser()
       parser.setFeature(xml.sax.handler.feature_namespaces, 0)
       Handler = CVEHandler()
       parser.setContentHandler( Handler )

       if self.trace:
          print ('Loading CVE data..')

       for file in self.filelist:
          if self.trace:
             print ("Loading file:", file )
          parser.parse(file)
       
       if self.trace:
          print ("CVE data loaded:", len(m_CVElist), "entries")        
 
       ret = []
       for v in ctypelist:
           
         vset = CVEsetbyVendor(str(v.getVendor()))   
         mset = CVEsetbyModel(str(v.getDesc()))         
         iset = vset & mset   # intersection set of vendor and model, e.g., Ford and F150
         
         if self.trace:
            print ("Search for", v.getVendor(), v.getDesc(), 'found', len(iset), 'CVEs' )
         
         if not(v.getType() == None ):
            if not(bool(iset)):
               eset = CVEsetbyType (str(v.getType()))
               iset = vset & eset  # intersection set of vendor and type, e.g., Ford and Pickup 
               if self.trace:
                  print ("Alt. search for", v.getVendor(), v.getType(), 'found', len(iset), 'CVEs' )        
     
         if bool(iset):
           if self.trace:
              print ('CVE list:', iset)
           cvelist = list(iset)           
  
           for s in cvelist:
               m_CVElist[s].setTarget (v.getDesc())
               m_CVElist[s].getEffects()
               m_CVElist[s].getAccess()
               ret.append (m_CVElist[s])
               v.addVulnerability (m_CVElist[s])
               
       return ret

