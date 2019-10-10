#Developer - K.Janarthanan
#Date - 20/9/2019
#Purpose - 
#   To webscrap "Hybrid Analysis" website; 
#   Get all File collection that are malicious; 
#   Get SHA256 files that are only malicious from the collection; 
#   Call "hybrid-analysis" APIs; 
#   Store the details in CSV

from urllib.request import Request, urlopen
import requests
from bs4 import BeautifulSoup
import json
import csv
import time

all_files=0 #Total no of files in all file collection
malicious=0 #Total no of malicious files
csv_data=[] #To hold all collected data

#Because only 39 pages are only accessible
for i in range(39):

    #Start url
    software_url ="https://www.hybrid-analysis.com/file-collections?page="+(str(i+1))

    print ("\nWorking on page : "+str(i+1))

    #Since this website blocks bots to do webscraping, we have to include the below header to make it believe that the requests comes from the web browser
    req = Request(software_url , headers={'User-Agent': 'Mozilla/5.0'})

    page = urlopen(req).read()

    soup= BeautifulSoup(page, 'html.parser')

    attack = soup.find('tbody', class_='rowlink')

    count=0
    
    for rows in attack.find_all('tr'):
        for columns in rows.find_all('td'):
            
            count+=1
            
            #Info on column 2 -> Individual file collection URL
            if (count==2):
                print("Moving to next file collection")
                link_url=columns.find('a')
                link="https://www.hybrid-analysis.com"+link_url['href']
                print("\nURL is : "+link)
                
                
            #Info on column 5 -> Whether file collection is 'malicious','no specific threat'
            if (count==5):
                attack_info=columns.get_text().strip()
                print ("Threat Level of file collection : "+attack_info+"\n")

                #We are interested in only malicious file collection only
                if(attack_info=="malicious"):

                    #Accessing individual file collection URL
                    req2 = Request(link , headers={'User-Agent': 'Mozilla/5.0'})

                    page2 = urlopen(req2).read()

                    soup= BeautifulSoup(page2, 'html.parser')

                    attack = soup.find('tbody', class_='rowlink')

                    n_count=0

                    for rows in attack.find_all('tr'):
                        for columns in rows.find_all('td'):
                            
                            n_count+=1

                            #Info on column 1 -> Information about 1 particular file
                            if (n_count==1):
                                try:
                                    link_url=columns.find('a')
                                    print("\nURL is : https://www.hybrid-analysis.com"+link_url['href'])
                                except:
                                    print ("unable to access element")

                            #Info on column 2 -> Getting the SHA256 value of the file
                            if (n_count==2):
                                
                                try:
                                    sha_256=columns.find('span')
                                    api_sha_256=sha_256['data-title']
                                    print("\nSHA256 is : "+api_sha_256)
                                except:
                                    print ("unable to access element")

                                
                            #Info on column 6 -> Getting the file  is 'malicious','no specific threat'
                            if (n_count==6):

                                try:
                                    attack_info=columns.get_text().strip()
                                    print ("Threat Level of file : "+attack_info+"\n")
                                    
                                    #We are interested only in malicious file only
                                    #We need to call API
                                    if (attack_info=="malicious"):
                                        
                                        print("calling API")

                                        headers={'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'text/plain', 'user-agent': 'Falcon Sandbox', 'accept': 'application/json','api-key': '4w0c8g0c4k80c4csck0cwk4w4csgosskkgsco0woc80cc8k0cwc4oc4kgkck8c0s'}

                                        pass_url="https://www.hybrid-analysis.com/api/v2/search/hash?_timestamp=1568892254741"   
                                        
                                        pass_data="hash="+api_sha_256

                                        p=requests.post(url=pass_url,data=pass_data,headers=headers)

                                        response= json.loads(p.text)
                                        ids=len(response)

                                        print ("Total ids : "+str(ids))
                                        print("\nJob ID : "+str(response[0]['job_id']))
                                        print("SHA256 value : "+response[0]['sha256'])

                                        mitre_techniques=[]
                                        tags=[]
                                        verdict_file="unable to retrieve"

                                        #Looping through Job IDs
                                        for i in range(ids):

                                            #Looping through Mitre Attack Techniques
                                            att=len(response[i]['mitre_attcks'])
                                            for j in range(att):
                                                print("mitre attack : "+str(response[i]['mitre_attcks'][j]['technique']))
                                                mitre_techniques.append(str(response[i]['mitre_attcks'][j]['technique']))

                                            #Looping through classification tags
                                            tag_no=len(response[i]['classification_tags'])
                                            for h in range(tag_no):
                                                print("classification tags : "+str(response[i]['classification_tags'][h]))
                                                tags.append(str(response[i]['classification_tags'][h]))

                                            if(response[i]['verdict']=="malicious"):
                                                verdict_file="malicious"
                                    
                                        print("Verdict : "+verdict_file)

                                        #Creating individual dictionary object
                                        my_data={}
                                        my_data['SHA256_Value']=response[0]['sha256']
                                        my_data['Verdict']=verdict_file
                                        my_data['Classification_tags']=list(set(tags)) #only getting unique attack techniques
                                        my_data['Mitre_Attack_Techniques']=list(set(mitre_techniques))                   

                                        #Putting Everything inside the list, if attack techniques > 0
                                        if(len(list(set(mitre_techniques)))!=0):
                                            csv_data.append(my_data)

                                        #Sleeping for 2s because 1 minute - 200 API calls, 1 hour - 2000 API calls
                                        time.sleep(2)                                      

                                        malicious+=1

                                    all_files+=1
                                except:
                                    print ("unable to access element")
                                
                            if (n_count==7):
                                n_count=0              
                
            if (count==6):
                count=0

#Putting collected data inside the CSV file
csv_columns=['SHA256_Value','Verdict','Classification_tags','Mitre_Attack_Techniques']

try:
    with open("myfinal.csv",'a',newline='') as csvfile:
        writer=csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()

        for data in csv_data:
            writer.writerow(data)

except:
    print("Error in creating CSV file")

print("Total files : "+str(all_files))
print("Total malicious files :  "+str(malicious))

