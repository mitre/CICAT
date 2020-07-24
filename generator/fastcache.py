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
fastcache.py - Utility to import ATT&CK data from portal and construct a JSON (cache) file
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
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
 