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
amodel.py - Object classes for ATT&CK dataset    
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


import time

def getTaGS(data):
    if (data):
       ret = data.lower().rstrip('.,;:\(\)').split(' ')
       return ret


class BASEOBJ:
    def __init__ (self, myID, created, modified, typex, desc, taglist, mytype):
        self.myID = myID
        self.created = created
        self.modified = modified
        self.typex = typex
        self.desc = desc
        self.taglist = taglist
        self.mytype = mytype
        
        self.uses = []
        self.mitigates = []
        self.relates = []
        self.revokes = []        
        self.tags = [] 
        
        self.tags = self.getTags()
                
    def getID(self):
        return self.myID
    
    def getType(self):
        return self.mytype
    
    def addUses(self, obj, desc):
        self.uses.append([obj,desc])
        
    def addMitigates(self, obj, desc):
        self.mitigates.append([obj,desc])
        
    def addRelates(self, obj, desc):
        self.relates.append([obj, desc])
        
    def addRevokes(self, obj, desc):
        self.revokes.append([obj, desc])
        
    def getUses(self):
        return self.uses
    
    def getMitigates(self):
        return self.mitigates
    
    def getRelates(self):
        return self.relates
    
    def getRevokes(self):
        return self.revokes
    
    def getCreated(self):
#        print ('Created:', time.strftime( "%Y-%m-%d %H:%M:%S", time.gmtime(self.created)))
        return self.created
    
    def getModified(self):
#        print ('Created:', time.strftime( "%Y-%m-%d %H:%M:%S", time.gmtime(self.modified)))
        return self.modified
    
    def getTypex(self):
        return self.typex
    
    def getDesc(self):
        return self.desc
    
    def createdTS (self):
        filterd = self.created.split('.')
        return time.mktime(time.strptime(filterd[0], "%Y-%m-%d %H:%M:%S"))
    
    def modifiedTS(self):
        filterd = self.modified.split('.')
        return time.mktime(time.strptime(filterd[0], "%Y-%m-%d %H:%M:%S"))   

    def getTimeFormat(self):
        return "%Y-%m-%d %H:%M:%S"

    def modifiedSince (self, tstTime):
        ctime = time.mktime(time.strptime(tstTime, "%Y-%m-%d %H:%M:%S"))
        if self.modifiedTS() > ctime:
            return True
        return False

    def isRevised(self):
        if self.modifiedTS() > self.createdTS():
            return True
        return False
        
    def getTags (self ):
        if (self.tags):
            return self.tags        
        if (self.taglist) and (self.desc):
           for x in self.taglist:
              if (self.desc.lower().find(x) > 0):
                  self.tags.append(x)
        return self.tags

    def hasTag(self, tag):
        if (self.desc):
           if (self.desc.find(tag) > 0):
               return True          
        return False

   
class THREATACTOR(BASEOBJ):

    taglist = ['government', 'education', 'institution', 'zero-day', 'firmware', 'bios', 'Middle East', 'open-source', 
               'espionage', 'disrupt','custom', 'china', 'PLA', 'GRU', 'russia', 'targeted', 'attack', 'north korea', 
               'foothold', 'persist', 'evasion', 'obfuscat', 'crypt', 'sophisticat', 
               'US', 'UK', 'israel', 'korea', 'iran', 'pakistan', 'criminal', 'japan', 'crime', 'skill', 'cyber', 
               'critical infrastructure', 'suspected', 'united states', 'united kingdom', 'europe', 'southeast asia', 
               'political', 'spearphish', 'remote access tool', 'Android', 'linux', 'windows', 'embedded', 'SCADA']
      
    def __init__ (self, created, created_by_ref, group, group_aliases, desc, 
                 group_id, group_references, ID, matrix, modified, typex, url):
       
       BASEOBJ.__init__(self, ID, created, modified, typex, desc, self.taglist, 'GROUP' )
       self.created_by_ref=created_by_ref
       self.group=group
       self.group_aliases=group_aliases
       self.group_id=group_id
       self.group_references= group_references
       self.matrix=matrix
       self.url=url
       self.getTags()
       self.sophistication = -1


    def getName(self):
        return self.group
    
    def getGroupID(self):
        return self.group_id
    
    def getPlaybook (self):
        return self.uses
    
    def getTTPList(self):
        ttplist = []
        pb = self.getPlaybook()
        for x in pb:
           if x[0].typex == 'attack-pattern': 
               ttplist.append (x[0])               
        return ttplist
        
    def getMalwareList(self):
        malist = []
        pb = self.getPlaybook()
        for x in pb:
           if x[0].typex == 'malware': 
               malist.append (x[0])               
        return malist
            
    def getToolsList(self):
        toolist = []
        pb = self.getPlaybook()
        for x in pb:
           if x[0].typex == 'tool': 
               toolist.append (x[0])               
        return toolist


    def getSophisticationLevel(self):
        if self.uses:
           self.sophistication = len (self.uses)        
        return self.sophistication
        
    def getAliases(self):
        return self.group_aliases
    
    def getURL(self):
        return self.url

    def getRefs (self):
        return self.group_references   
    
    def PP(self):
        print ('\nACTOR:', self.group )
        print ('Tag(s):', self.getTags() )


class CYBERTOOL(BASEOBJ):
    
    taglist = ['vulnerability', 'schedule', 'script', 'batch', 'command-line', 'configur', 'remote', 
               'execut', 'open source', 'cross-platform', 'Windows utility', 'command-line', 
               'powershell', 'shell', 'remote access tool', 'scan', 'penetration', 'test', 'ploit' ]
    
    def __init__ (self, created, created_by_ref, ID, matrix, modified, software, software_aliases, desc,
                  software_id, software_labels, software_platform, software_references, typex, url):

        BASEOBJ.__init__(self, ID, created, modified, typex, desc, self.taglist, 'TOOL' )
        self.created_by_ref=created_by_ref
        self.matrix=matrix
        self.software=software
        self.software_aliases=software_aliases
        self.software_id=software_id
        self.software_labels=software_labels
        self.software_platform=software_platform
        self.software_references=software_references
        self.url=url

    def getName(self):
        return self.software
    
    def getSID(self):
        return self.software_id
    
    def getAliases(self):
        return self.software_aliases
    
    def getRefs(self):
        return self.software_references
    
    def getPlatform(self):
        return self.software_platform
    
    def PP(self):
        print ('\nTOOL:', self.software )
        print ('Tag(s):', self.getTags() )


    
class MALWARE(BASEOBJ):
    
    taglist = ['virus', 'trojan', 'spyware', 'worm', 'remote access tool', 'RAT', 
               'stolen', 'steal', 'backdoor', 'crypt', 'adware','obfuscat' ] 
    
    def __init__ (self, created, created_by_ref, ID, matrix, modified, software, software_aliases, 
                  desc, software_id, software_labels, software_platform, software_references,
                  typex, url):

        BASEOBJ.__init__(self, ID, created, modified, typex, desc, self.taglist, 'MALWARE' )
        self.created_by_ref=created_by_ref
        self.matrix=matrix
        self.software=software
        self.software_aliases= software_aliases
        self.software_id= software_id
        self.software_labels= software_labels
        self.software_platform= software_platform
        self.software_references= software_references
        self.url =url

    def getName(self):
        return self.software
    
    def getSID(self):
        return self.software_id
    
    def getAliases(self):
        return self.software_aliases
    
    def getRefs(self):
        return self.software_references
    
    def getPlatform(self):
        return self.software_platform
    
    def PP(self):
        print ('\nMALWARE:', self.software )
        print ('Tag(s):', self.getTags() )



class TTP(BASEOBJ):

    taglist = [ 'discretionary', 'access','permission', 'persistence','command-line', 'bypass','whitelist','arbitrary commands',
                'remote access', 'session','connection','manipulate', 'Active Directory','Domain Controller', 'inject','credential',
                'privilege','exploitation','vulnerability', 'programming error','kernel','operating system','authentication',
                'circumvent','Kerberos','ticket','protocol','windows','network','file sharing','connect','WebDAV','spearphish',
                'browser','intercept','man in the','cookie','SSL','TLS','pivot','HTTP proxy','redirect','sharepoint','webmail',
                '2-factor','API','DLL','Hook','malware','Microsoft','Windows','Linux','cache','database','user mode','kernel mode',
                'digital signature','XML','property list','macro','background job','cron','secure shell','history','flush','ignore',
                'sudo','least privilege','password','hijack','gateway','remote service','agent','SNMP','root','public key',
                'certificate authority','trust','degrade','avoid','warning','man-in-the','reverse engineer','MSbuild','WinDbg',
                'cdb.exe','capture','exfiltrat','record','InstallUtil','smart card','keylogger','securID','passcode','firmware',
                'BIOS','evade','integrity check','registry','plaintext','SCADA','controller','process-control' ]                           
            
    
    def __init__ (self, capec_id, capec_url, contributors, created, created_by_ref, data_sources, defense_bypassed,
                  detectable_by_common_defenses, detectable_explanation, difficulty_explanation, difficulty_for_adversary,
                  effective_permissions, ID, matrix, modified, network_requirements, object_marking_refs,
                  permissions_required, platform, remote_support, system_requirements, tactic, tactic_type,
                  technique, desc, technique_detection, technique_id, technique_references, typex ):

        BASEOBJ.__init__(self, ID, created, modified, typex, desc, self.taglist, 'TTP' )
        self.capec_id=capec_id
        self.capec_url=capec_url
        self.contributors=contributors
        self.created_by_ref=created_by_ref
        self.data_sources=data_sources
        self.defense_bypassed=defense_bypassed
        self.detectable_by_common_defenses=detectable_by_common_defenses
        self.detectable_explanation=detectable_explanation
        self.difficulty_explanation=difficulty_explanation
        self.difficulty_for_adversary=difficulty_for_adversary
        self.effective_permissions=effective_permissions
        self.matrix=matrix
        self.network_requirements=network_requirements
        self.object_marking_refs=object_marking_refs
        self.permissions_required=permissions_required
        self.platform=platform
        self.remote_support=remote_support
        self.system_requirements=system_requirements
        self.tactic=tactic
        self.tactic_type=tactic_type
        self.technique=technique
        self.technique_id = technique_id
        self.technique_detection=technique_detection
        self.technique_references=technique_references      
        self.Psuccess = 0
        self.breadcrumbs = 1
        self.coas = []
        
        if (self.technique_detection):
            self.breadcrumbs = self.technique_detection.count('.')  
            # assumes breadcrumbs proportional to number of sentences in technque_detection

    def getName(self):
       return self.technique
   
    def getTECHID(self):
        return self.technique_id

    def addCOA(self, coa, desc):
       self.coas.append([coa, desc])

    def getCOA(self):
        return self.coas
    
    def getDET(self):
        return self.technique_detection
    
    def getTactic(self):
        return self.tactic
    
    def getPlatform(self):
        return self.platform
    
    def setP(self, value):
        self.Psuccess = value
        
    def setBreadcrumbs(self, value):
        self.breadcrumbs = value
        
    def getP(self):
        return self.Psuccess
    
    def getBreadcrumbs(self):
        return self.breadcrumbs
    
    def getURL(self):
        if (self.technique_references):
           return self.technique_references[0]

    def PP(self):
        cnt = 0
        maxwc = 30
        shortdesc = ''
        wlist = self.getDesc().split(' ')
        if wlist:            
            for j in wlist:
                shortdesc = shortdesc + ' ' + j
                cnt = cnt + 1
                if cnt > maxwc:
                    shortdesc = shortdesc + '...'
                    break                
        print (self.getTECHID(), ':', self.technique, '-', shortdesc.lstrip())
#        print ('Tag(s):', self.getTags() )





class MIT(BASEOBJ):

    taglist = ['prevent', 'detect', 'incident', 'response', 'patch', 'scan', 'monitor', 'sensor', 
               'whitelist', 'configuration', 'harden', 'verify', 'inspect', 'validate', 'review', 
               'access', 'privilege', 'password', 'authenticat' ]
    
    def __init__ (self, created, created_by_ref, ID, matrix, mitigation, desc, 
                  mitigation_references, modified, technique_id, typex, url ):       

        BASEOBJ.__init__(self, ID, created, modified, typex, desc, self.taglist, 'MIT' )
        self.created_by_ref=created_by_ref
        self.matrix=matrix
        self.mitigation=mitigation
        self.mitigation_references=mitigation_references
        self.technique_id=technique_id
        self.url=url

    def getName(self):
        return self.mitigation
    
    def getTECHID(self):
        return self.technique_id

    def getURL(self):
        if (self.mitigation_references):
           return self.mitigation_references[0]
    
    def bPrevent(self):
        tlist = self.getTags()
        if tlist:
            if ('prevent' in tlist):
                return True
        return False
    
    def bDetect(self):
        tlist = self.getTags()
        if tlist:
            if ('detect' in tlist):
                return True
        return False
    
    def bMitigate(self):
        tlist = self.getTags()
        if tlist:
            if ('response' in tlist):
                return True
        return False


    def PP(self):
        print ('\nMitigation Name:', self.technique_id)
        print ('Description:', self.mitigation)
        print ('Reference:', self.url)
        print ('Tag(s):', self.getTags() )


class ATKRELATION():

    def __init__ (self, created, created_by_ref, ID, modified, rship_name, rship_desc, src_obj, tgt_obj):
        self.created = created
        self.created_by_ref = created_by_ref
        self.myID = ID
        self.modified = modified
        self.rship_name = rship_name
        self.rship_desc = rship_desc
        self.src_obj = src_obj
        self.tgt_obj = tgt_obj

