#Developer - K.Janarthanan
#Date - 20/9/2019
#Purpose - 
#   Call "hybrid-analysis" APIs; 
#   Store the details in CSV

import json
import requests
import sys
import csv

headers={'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'text/plain', 'user-agent': 'Falcon Sandbox', 'accept': 'application/json','api-key': 'xxxx'}
pass_url="https://www.hybrid-analysis.com/api/v2/search/hash?_timestamp=1568892254741"   
#pass_data="hash=3f128fb1f98e4b90584b14cb29663cea46986457f51552983fb57be29e2a771a"
pass_data="hash=b954a29f71e501e9c7b144b6d9ff5a2f9cd96021965123c6cc8ee900312d46c5"

p=requests.post(url=pass_url,data=pass_data,headers=headers)


response= json.loads(p.text)
count=len(response)


print ("Total ids : "+str(count))
print("\nJob ID : "+str(response[0]['job_id']))
print("SHA256 value : "+response[0]['sha256'])
print("Verdict : "+response[0]['verdict'])
#print("Domain : "+response[0]['domains'][1])

#att=len(response[0]['mitre_attcks'])
#print("total no of attacks techniques : " +str(att))
print("mitre attack : "+str(response[0]['mitre_attcks'][1]['technique']))

print("\n********************")

mitre_techniques=[]
tags=[]
#Looping through Job IDs
for i in range(count):

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

#print(mitre_techniques)
#print(tags)

#Store only unique techniques, tags, SHA256, verdict -> CSV or JSON

my_data={}
my_data['SHA256_Value']=response[0]['sha256']
my_data['Verdict']=response[0]['verdict']
my_data['Classification_tags']=list(set(tags))
my_data['Mitre_Attack_Techniques']=list(set(mitre_techniques))

csv_columns=['SHA256_Value','Verdict','Classification_tags','Mitre_Attack_Techniques']
csv_data=[my_data]

try:
    with open("myCSV.csv",'w') as csvfile:
        writer=csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()

        for data in csv_data:
            writer.writerow(data)

except:
    print("Error in creating CSV file")
