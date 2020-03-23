# -*- coding: utf-8 -*-
"""
Created on Tue Feb 25 15:46:34 2020

@author: JWYNN
"""

from attackcti import attack_client
import json
import os
import sys


attack_data = None 


# main entry point
if ( __name__ == "__main__"):   
    
   cachefilename = 'attack.json'
   
   params = sys.argv
   if len(params) > 1:
        cachefilename =  params[1].lower()
   
   try: 
     with open(os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'data', 'ATK', cachefilename ))) as data_file:    
         attack_data = json.load(data_file)
         
     print ('ATT&CK cache loaded.')
     
   except FileNotFoundError:
       print ('ATT&CK cache', cachefilename, 'not found. Refreshing from STIX/TAXII service.' )
       
       ac = attack_client()
       attack_data = ac.get_all_stix_objects()
       
       if not(attack_data):
           print ('No ATT&CK data retrieved from STIX//TAXII service.')
           exit

       try:
          
           with open ((os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'data', 'ATK', cachefilename ))), mode="w+") as outfile:
               json.dump(attack_data, outfile)
               
           print ('ATT&CK cache', cachefilename, 'recreated from STIX/TAXII service.' )
           
       except:
           print ('Error retrieving data from ATT&CK portal.')
           raise
    

   print ('end of run')
 