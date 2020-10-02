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
dbLoad.py - Utility for constructing and populating a mySQL database with imported data 
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


import sys
import mysql.connector
from mysql.connector import errorcode

from collections import defaultdict
from loaddata import LOAD_DATA
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS

from os import path
sys.path.append(path.normpath(path.join(path.dirname(__file__), "..")))
from cicat2.settings import DATABASES

m_DATASET = defaultdict(list )


db_TABLES = {}

db_TABLES['vulnerability'] = (
      "CREATE TABLE `vulnerability` ("
      " `cve` varchar(16) NOT NULL,"
      " `description` varchar(4096),"
      " `reference` varchar(1024),"
      " `ctid` varchar(16),"    # FK maps to ctype [id]
      " PRIMARY KEY (`cve`)"
      ") ENGINE=InnoDB" )

db_TABLES['ctype'] = (
    "CREATE TABLE `ctype` ("
      " `idx` varchar(16) NOT NULL,"
      " `vendor` varchar(64),"
      " `description` varchar(4096),"
      " `typex` varchar(64)," 
      " `platform` varchar(16),"
      " PRIMARY KEY (`idx`)"
      ") ENGINE=InnoDB" )

db_TABLES['component'] = (
      "CREATE TABLE `component` ("
      " `idx` varchar(16) NOT NULL,"
      " `ctid` varchar(16) NOT NULL,"  # FK maps to ctype [id] 
      " `ipaddr` varchar(32),"
      " `systemz` varchar(128),"    # FK maps to system [name]
      " `criticality` varchar(64),"
      " PRIMARY KEY (`idx`)"
      ") ENGINE=InnoDB" )

db_TABLES['systemz'] = (
     "CREATE TABLE `systemz` ("
     "`name` varchar(64) NOT NULL,"
     "`description` varchar(4096),"
     "`level` varchar(8),"          # FK maps to Location [level]
     "`zone` varchar(8),"           # FK maps to Location [zone]
     "`criticality` varchar(64),"
     " PRIMARY KEY (`name`)"
     ") ENGINE=InnoDB" )

db_TABLES['fsmap'] = (
     "CREATE TABLE `fsmap` ("
     "`fname` varchar(64) NOT NULL,"   # FK maps to function [name]
     "`sname` varchar(64) NOT NULL,"   # FK maps to system [name]
     " PRIMARY KEY (`fname`, `sname`)"
     ") ENGINE=InnoDB" )
        
db_TABLES['functionz'] = (       
    "CREATE TABLE `functionz` ("
    "`name` varchar(64) NOT NULL,"
    "`description` varchar(4096),"
    "`capability` varchar(64),"    # FK maps to capability [name]
    "`criticality` varchar(64),"
    " PRIMARY KEY (`name`)"
    ") ENGINE=InnoDB" )

db_TABLES['capability'] = (       
    "CREATE TABLE `capability` ("
    "`name` varchar(64) NOT NULL,"
    "`description` varchar(4096),"
    "`criticality` varchar(64),"
    " PRIMARY KEY (`name`)"
    ") ENGINE=InnoDB" )

db_TABLES['surface'] = (
    "CREATE TABLE `surface` ("
    "`component` varchar(32) NOT NULL," # FK maps to component description
    "`surftype` varchar(32) NOT NULL,"
    "`access` varchar(8),"
    " PRIMARY KEY (`component`,`surftype`)"
    ") ENGINE=InnoDB")

db_TABLES['location'] = (
    "CREATE TABLE `location` ("
    "`level` varchar(8) NOT NULL,"
    "`zone` varchar(8) NOT NULL,"
    "`description` varchar(256),"
    "`owner` varchar(128),"
    "`access` varchar(8),"
    " PRIMARY KEY (`level`,`zone`)"
    ") ENGINE=InnoDB")       
        

db_TABLES['attack'] = (
    "CREATE TABLE `attack` ("
    "`capec_id` varchar(128),"
    "`capec_url` varchar(256),"
    "`contributors` varchar(512),"
    "`date_created` varchar(64),"
    "`created_by_ref` varchar(128),"
    "`data_sources` varchar (512),"
    "`defense_bypassed` varchar(750),"
    "`detectable_by_common_defenses` varchar(32),"
    "`detectable_explanation` varchar(850),"  
    "`difficulty_explanation` varchar(750),"
    "`difficulty_for_adversary` varchar(32),"
    "`effective_permissions` varchar(128),"
    "`myID` varchar(128),"
    "`matrix` varchar(64),"
    "`date_modified` varchar(64),"
    "`network_requirements` varchar(16),"
    "`object_marking_refs` varchar(512),"
    "`permissions_required` varchar(64),"
    "`platform` varchar(32),"
    "`remote_support` varchar(16),"
    "`system_requirements` varchar(512),"
    "`tactic` varchar(128),"
    "`tactic_type` varchar(64),"
    "`tech_name` varchar(256),"
    "`tech_desc` varchar(6000),"
    "`tech_detect` varchar(2750),"
    "`tech_id` varchar(16) NOT NULL,"
    "`tech_references` varchar(1500),"
    "`typex` varchar(16),"
    " PRIMARY KEY (`tech_id`)" 
    ") ENGINE=InnoDB")  

db_TABLES['atkmit'] = (
    "CREATE TABLE `atkmit` ("
    "`date_created` varchar(64),"
    "`created_by_ref` varchar(128),"
    "`myID` varchar(128),"
    "`matrix` varchar(64),"
    "`mit_name` varchar(256),"
    "`mit_desc` varchar(8192),"
    "`mit_references` varchar(1500),"
    "`date_modified` varchar(64),"
    "`tech_id` varchar(16) NOT NULL,"
    "`typex` varchar(16),"
    "`mit_url` varchar(256),"
    " PRIMARY KEY (`tech_id`)"
    ") ENGINE=InnoDB")

db_TABLES['atkmal'] = (
    "CREATE TABLE `atkmal` ("
    "`date_created` varchar (64),"
    "`created_by_ref` varchar(128),"
    "`myID` varchar(128),"
    "`matrix` varchar (128),"
    "`date_modified` varchar(64),"
    "`mal_name` varchar(256),"
    "`mal_aliases` varchar(1024),"
    "`mal_desc` varchar(8192),"
    "`mal_id` varchar(16) NOT NULL,"
    "`mal_labels` varchar (512),"
    "`platform` varchar (128),"
    "`mal_references` varchar(1500),"
    "`typex` varchar(16),"
    "`mal_url` varchar(256),"
    " PRIMARY KEY (`mal_id`)"
    ") ENGINE=InnoDB")


db_TABLES['atktool'] = (
    "CREATE TABLE `atktool` ("
    "`date_created` varchar(64),"
    "`created_by_ref` varchar (128),"
    "`myID` varchar(128),"
    "`matrix` varchar (128),"
    "`date_modified` varchar(64),"
    "`tool_name` varchar (256),"
    "`tool_aliases` varchar (1024),"
    "`tool_desc` varchar (8192),"
    "`tool_id` varchar(16) NOT NULL,"
    "`tool_labels` varchar(512),"
    "`platform` varchar(128),"
    "`tool_references` varchar(1500),"
    "`typex` varchar(16),"
    "`tool_url` varchar(256),"
    " PRIMARY KEY (`tool_id`)"
    ") ENGINE=InnoDB")    

db_TABLES['atkactor'] = (
    "CREATE TABLE `atkactor` ("
    "`date_created` varchar (64),"
    "`created_by_ref` varchar (128),"
    "`act_name` varchar (256),"
    "`act_aliases` varchar (1024),"
    "`act_desc` varchar (8192),"
    "`act_id` varchar (16) NOT NULL,"
    "`act_references` varchar (2048),"
    "`myID` varchar(128),"
    "`matrix` varchar(128),"
    "`date_modified` varchar(64),"
    "`typex` varchar(16),"
    "`act_url` varchar(256),"
    " PRIMARY KEY (`act_id`)"
    ") ENGINE=InnoDB")
    
db_TABLES['actcap'] = (        
    "CREATE TABLE `actcap` ("
    "`act_id` varchar (16) NOT NULL,"
    "`tech_id` varchar(16) NOT NULL,"
    "`capnotes` varchar(1024),"
    " PRIMARY KEY (`act_id`, `tech_id`)"
    ") ENGINE=InnoDB")


db_TABLES['target'] = (
    "CREATE TABLE `target` ("
    "`target_id` varchar (16) NOT NULL,"
    "`target_type` varchar (16),"
    "`target_name` varchar (64),"
    " PRIMARY KEY (`target_id`)"
    ") ENGINE=InnoDB")

db_TABLES['scenario'] = (
    "CREATE TABLE `scenario` ("
    "`scn_id` varchar (16) NOT NULL,"
    "`scn_shortname` varchar (32), "
    "`scn_name` varchar (128),"
    "`scn_desc` varchar (512),"
    "`scn_detail` text (30000),"
    "`scn_actor` varchar (32),"
    "`scn_intent` varchar (32),"
    "`scn_targetid` varchar (32),"
    " PRIMARY KEY (`scn_id`)"
    ") ENGINE=InnoDB" )
    

def list2string (listx):
    if not(listx):
        return None 
    
    ret = listx[0]
    for x in listx[1:]:
        ret = ret + '; ' + x
    return ret

def create_database(cursor, dbName):
    try:
        cursor.execute("CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'".format(dbName))
    except mysql.connector.Error as err:
        print("Failed creating database: {}".format(err))

    try:
        cursor.execute("USE {}".format(dbName))
    except mysql.connector.Error as err:
        print("Database {} does not exists.".format(dbName))
    if err.errno == errorcode.ER_BAD_DB_ERROR:
        create_database(cursor)
        print("Database {} created successfully.".format(dbName))
    else:
        print(err)


def dbconnect (dbName):
    try:
        #db connection string needs to be parameterize, must update to match settings on local host
        db = DATABASES['default']
        cnx = mysql.connector.connect(user=db['USER'], 
            password=db['PASSWORD'],
            host=db['HOST'], 
            database=dbName)
        cnx.database = dbName
        return cnx 
    except mysql.connector.Error as err:
        print ('dbconnect:', err)
        

def initDB (dbName):
    cnx = dbconnect (dbName)
    cursor = cnx.cursor()  
    create_database(cursor, dbName )
    cnx.close()
   
   
def addtable(dbName, tblName, trace):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()             
   desc = db_TABLES[tblName]
   try:
      cursor.execute(desc)
      cnx.commit()
      cursor.close()
      cnx.close()
      if trace:
         print ("Table", tblName, "added to database", dbName)

   except mysql.connector.Error as err:
      print ('addtable:', err)
   

def droptable(dbName, tblname, trace):
   cnx = dbconnect(dbName)
   cursor = cnx.cursor()    
   cmd = ("DROP table `"+ tblname + "`")
        
   try:
      cursor.execute (cmd) 
      cnx.commit()
      cursor.close()
      cnx.close()
      if trace:
         print ("Table", tblname, "dropped from database", dbName)
      
   except mysql.connector.Error as err:
      print('droptable:', err)


def storeCOA (dbName, coa): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO coa VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" )     
   data = (coa.getID(), coa.getName(), coa.getDescription(), coa.getEffect(), 
           coa.getApplication(), coa.getMaturity(), coa.getCost(), coa.getReference() )

   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeCOA:', err)
    

def storeVector (dbName, vector): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO vector VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" )    
   data = (vector.getID(), vector.getName(), vector.getType(), vector.getDescription(), vector.getObjective(), 
           vector.getPreqs(), vector.getReqACTCAP(), vector.getReference() )      

   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeVector:', err)

def storeVULNERABILITY (dbName, ctid, vuln): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO vulnerability VALUES (%s, %s, %s, %s )" )  
   data = (vuln.getCVE(), vuln.getDescription(), 
           list2string (vuln.getReferences()), str(ctid ) )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeVULNERABILITY:', err)

def storeCTYPE (dbName, cmp): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO ctype VALUES (%s, %s, %s, %s, %s)" )    
   data = (cmp.getID(), cmp.getVendor(), cmp.getDesc(),  cmp.getType(), cmp.getPlatform() )
  
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeCTYPE:', err)
      
def storeCOMPONENT (dbName, ctid, cmp): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO component VALUES (%s, %s, %s, %s, %s)" )  
   data = (cmp.getID(), str(ctid), cmp.getIPAddress(), cmp.getSystem().getName(), str(cmp.getImpactScore()) )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeCOMPONENT:', err)


def storeSYSTEM (dbName, sys): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO systemz VALUES (%s, %s, %s, %s, %s)" )  
   data = (sys.getName(), sys.getDescription(), str(sys.getLevel()), 
           sys.getZone(), list2string(sys.getCriticality()) )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeSYSTEM:', err)

def storeFUNCTION (dbName, fx): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO functionz VALUES (%s, %s, %s, %s)" )  
   data = (fx.getName(), fx.getDescription(), fx.getCapability(), list2string(fx.getCriticality() ) )
   
   try:      
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeFUNCTION:', err)

def storeFSMAP (dbName, mapentry ):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()
   
   if not(mapentry.getFunction()) or not (mapentry.getSystem()):
        return

   cmd = ("INSERT INTO fsmap VALUES (%s, %s)" )  
   data = (mapentry.getFunction(), mapentry.getSystem() )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeFSMAP:', err)


def storeCAPABILITY (dbName, cap): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO capability VALUES (%s, %s, %s)" )  
   data = (cap.getName(), cap.getDescription(),  cap.getCriticality() )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeCAPABILITY:', err)

def storeSURFACE (dbName, ep): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO surface VALUES (%s, %s, %s)" )  
   data = (ep.getComponent(), ep.getSurfaceType(),  ep.getAccess() )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeSURFACE:', err)


def storeLOCATION (dbName, loc): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO location VALUES (%s, %s, %s, %s, %s)" )  
   data = (loc.getLevel(), loc.getZone(), loc.getFacility(), loc.getOwner(), loc.getAccess() )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeLOCATION:', err)

def storeTARGET (dbName, tgt): 
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO target VALUES (%s, %s, %s)" )  
   data = (tgt.getTID(), tgt.getType(), tgt.getName() )
   
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeTARGET:', err)

def storeSCENARIO (dbName, scn):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()          

   cmd = ("INSERT INTO scenario VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" )  
   data = (scn.getID(), scn.getShortName(), scn.getName(), scn.getDesc(), scn.getDetail(), 
           scn.getActorID(), scn.getIntendedEffect(), scn.getTargetID() )
  
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeSCENARIO:', err)
      
def refreshSCENARIOs (dataset, trace, dbname='cicat20'):   
    
    droptable (dbname, 'scenario', trace)
    addtable (dbname, 'scenario', trace)
        
    for s in dataset['SCENARIO']:
        if trace:
            print ('updateSCENARIO: storing scenario', s.getID())
            
        storeSCENARIO (dbname, s)   


def findctype (desc ):
    for j in m_DATASET['CTYPE']:
        if (desc == j.getDesc()):
            return j


def storeATKTechnique (dbName, atk):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()      

   cmd = ("INSERT INTO attack VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, \
                                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, \
                                        %s, %s, %s, %s, %s )" )                                        
   data = (str(atk.capec_id), 
           str(atk.capec_url), 
           str(atk.contributors), 
           str(atk.created),
           str(atk.created_by_ref), 
           str(atk.data_sources), 
           str(atk.defense_bypassed), 
           str(atk.detectable_by_common_defenses),
           str(atk.detectable_explanation), 
           str(atk.difficulty_explanation), 
           str(atk.difficulty_for_adversary),
           str(atk.effective_permissions),
           str(atk.myID),
           str(atk.matrix), 
           str(atk.modified),
           str(atk.network_requirements), 
           str(atk.object_marking_refs), 
           str(atk.permissions_required),
           str(atk.platform), 
           str(atk.remote_support), 
           str(atk.system_requirements),
           str(atk.tactic), 
           str(atk.tactic_type), 
           str(atk.technique),
           str(atk.desc),
           str(atk.technique_detection), 
           str(atk.technique_id), 
           str(atk.technique_references),
           str(atk.typex)  )

   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeATKTechnique:', atk.technique_id, 'Error:', err)


def storeATKMitigation (dbName, mit):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()      
    
   cmd = ("INSERT INTO atkmit VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")                              
   data = (str(mit.created), 
           str(mit.created_by_ref), 
           str(mit.myID), 
           str(mit.matrix), 
           str(mit.mitigation), 
           str(mit.desc),
           str(mit.mitigation_references), 
           str(mit.modified), 
           str(mit.technique_id), 
           str(mit.typex), 
           str(mit.url) )
      
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeATKMitigation:', mit.technique_id, 'Error:', err)


def storeATKMAL (dbName, mal):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()      
    
   cmd = ("INSERT INTO atkmal VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")    
                          
   data = (str(mal.created), 
           str(mal.created_by_ref), 
           str(mal.myID), 
           str(mal.matrix), 
           str(mal.modified), 
           str(mal.software),
           str(mal.software_aliases), 
           str(mal.desc), 
           str(mal.software_id), 
           str(mal.software_labels), 
           str(mal.software_platform),
           str(mal.software_references), 
           str(mal.typex), 
           str(mal.url) )
                
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeATKMAL', mal.software_id, 'Error:', err)


def storeATKTOOL (dbName, tool):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()      
    
   cmd = ("INSERT INTO atktool VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")    
                          
   data = (str(tool.created), 
           str(tool.created_by_ref), 
           str(tool.myID), 
           str(tool.matrix), 
           str(tool.modified), 
           str(tool.software),
           str(tool.software_aliases), 
           str(tool.desc), 
           str(tool.software_id), 
           str(tool.software_labels), 
           str(tool.software_platform), 
           str(tool.software_references), 
           str(tool.typex), 
           str(tool.url) )
                
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeATKTOOL:', tool.software_id, 'Error:', err)


def storeATKACTOR (dbName, act):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()      
    
   cmd = ("INSERT INTO atkactor VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")    
                          
   data = (str(act.created), 
           str(act.created_by_ref), 
           str(act.group), 
           str(act.group_aliases), 
           str(act.desc), 
           str(act.group_id), 
           str(act.group_references), 
           str(act.myID), 
           str(act.matrix), 
           str(act.modified),
           str(act.typex), 
           str(act.url) )
                
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeATKACTOR:', act.group, 'Error:', err)
           
def storeACTCAP (dbName, act_id, tech_id, desc):
   cnx = dbconnect (dbName)
   cursor = cnx.cursor()      
    
   cmd = ("INSERT INTO actcap VALUES (%s, %s, %s)")                            
   data = (act_id, tech_id, desc )
                
   try:
      cursor.execute (cmd, data)
      cnx.commit()
      cursor.close()
      cnx.close()
      
   except mysql.connector.Error as err:
      print('storeACTCAP:', act_id,'tech_id', tech_id, 'Error:', err)
           

def loadACTCAP(dbname, actor):    
    caplist = actor.getUses()
    for c in caplist:
        if c[0].getType() == 'attack-pattern':
            storeACTCAP (dbname, actor.group_id, c[0].technique_id, c[1])


CVEFiles = ["CVE\CVE-year-2018.xml", "CVE\CVE-year-2017.xml", "CVE\CVE-year-2016.xml"]


# main entry point
if ( __name__ == "__main__"):
    
#   Load database from JSON data (default)
    loadopt = 'JSON'
    fname = None
    dbName = 'atomic_py'  # Note: the database must be created prior to running this utility
    trace = True #True
    
    params = sys.argv
    if (len(params) == 1):
        print ('Loading ATT&CK data from local JSON file')
    elif (len(params) > 1 ) and not(params[1] == 'help'): # params[1] = spreadsheet to load
        print ('Loading ATT&CK data from spreadsheet:', params[1])
        loadopt = 'SPREAD'
        fname = params[1]
    else:
        print ('Usage:', params[0], '[<ATT&CK Excel file>]')
        exit()
              
    m_DATASET = LOAD_DATA (m_file_INFRASTRUCTURE, m_file_SCENARIOS, True, False)
    
    initDB (dbName)

    if trace:
        print ('Initializing database tables...')
    for m in db_TABLES.keys():
        droptable (dbName, m, trace)
        addtable (dbName, m, trace)

    if trace:
        print ('Storing CTYPE data...')
    for ct in m_DATASET['CTYPE']:
        storeCTYPE (dbName, ct)

    if trace:
        print ('Storing COMPONENT data...')
    for c in m_DATASET['COMPONENT']:
        ct = findctype(c.getDesc() )
        storeCOMPONENT(dbName, ct.getID(), c)
   
    if trace:
        print ('Storing SYSTEM data...')
    for s in m_DATASET['SYSTEM']:
        storeSYSTEM(dbName, s)
    
    if trace:
        print ('Storing FUNCTION data...')
    for f in m_DATASET['FUNCTION']:
        storeFUNCTION (dbName, f)
        
    if trace:
        print ('Storing FSMAP data...')
    for fs in m_DATASET['FSMAP']:
        storeFSMAP (dbName, fs)
        
    if trace:
        print ('Storing CAPABILITY data...')
    for c in m_DATASET['CAPABILITY']:
        storeCAPABILITY (dbName, c)     

    if trace:
        print ('Storing SURFACE data...')
    for e in m_DATASET['SURFACE']:
        storeSURFACE (dbName, e)  

    if trace:
        print ('Storing LOCATION data...')
    for l in m_DATASET['LOCATION']:
        storeLOCATION (dbName, l)  

    if m_DATASET['VULNERABILITY'] and trace:
        print ('Storing VULNERABILITY data...')
    for v in m_DATASET['VULNERABILITY']:
        ct = findctype(v.getTarget() )
        storeVULNERABILITY (dbName, ct.getID(), v)    
        
    if m_DATASET['TARGET'] and trace:
        print ('Storing TARGET data...')
    for t in m_DATASET['TARGET']:
        storeTARGET (dbName, t)
        
    if trace:
        print ('Storing ATT&CK TTP data...')
    for t in m_DATASET['ATT&CK']:
        storeATKTechnique (dbName, t)
        
    if trace:
        print ('Storing ATT&CK Mitigation data...')
    for t in m_DATASET['ATKMITIGATION']:
        storeATKMitigation (dbName, t)
        
    if trace:
        print ('Storing ATT&CK Malware data...')
    for t in m_DATASET['ATKMALWARE']:
        storeATKMAL (dbName, t)
   
    if trace:
        print ('Storing ATT&CK Tool data...')
    for t in m_DATASET['ATKTOOL']:
          storeATKTOOL (dbName, t)
        
    if trace:
        print ('Storing ATT&CK Group data...')
    for t in m_DATASET['ATKGROUPS']:
        storeATKACTOR(dbName, t)

    if trace:
        print ('Storing ACTCAP data...')
    for t in m_DATASET['ATKGROUPS']:
        loadACTCAP(dbName, t)

    if trace:       
       print ('End of run')
    
          
