#Developer -  K.Janarthanan
#Purpose - In order to collect filename corresponding to its hash value
# Date - 27/9/2019

#Read the CSV file
#Access API to get associated file name
#Store data into new CSV file

import csv
import requests
import time
import json
#Reading CSV files
all_files=[]


#Pass the extracted CSV file from Hybrid-Analysis
with open('Classified_Final.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count=0
    no_results=0

    for row in csv_reader:

        my_dic={}

        if (line_count==0):
            line_count+=1

        else:
            
            my_dic['SHA256_Value']=row[0]
            my_dic['Tags']=row[1]
            my_dic['Score']=row[2]
            my_dic['AV_Labels']=row[3]
            my_dic['Attack_Techniques']=row[4]
            my_dic['All_Categories']=row[5]
            my_dic['Classified_Label']=row[6]

            #Calling Hybrid API
            try:
                
                print("calling API")

                headers={'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'text/plain', 'user-agent': 'Falcon Sandbox', 'accept': 'application/json','api-key': 'xxxx'}

                pass_url="https://www.hybrid-analysis.com/api/v2/search/hash?_timestamp=1568892254741"   
                                        
                pass_data="hash="+row[0]

                p=requests.post(url=pass_url,data=pass_data,headers=headers)

                response= json.loads(p.text)
                ids=len(response)

                print ("Total ids : "+str(ids))

                #Looping through Job IDs
                for i in range(ids):
                    
                    if not (response[i]['submit_name']):
                        my_dic['File_Name']="None"
                        no_results+=1

                    else:
                        my_dic['File_Name']=response[i]['submit_name']
                        break
                                    

            except:
                my_dic['File_Name']="None"
                no_results+=1

            line_count+=1

        #Only 200 APIs are allowed in 1 minute
        #time.sleep(1)

        all_files.append(my_dic)
        print("Next File .....\n")
            
csv_file.close()

print("Goint to create new CSV")

#Write to the CSV file
csv_columns=['SHA256_Value','File_Name','Tags','Score','AV_Labels','Attack_Techniques','All_Categories','Classified_Label']

try:
    with open("FileName_With_SHA256.csv",'a',newline='',encoding='utf-8') as csvfile:
        writer=csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()

        for data in all_files:
            writer.writerow(data)

except:
    print("Error in creating CSV file")

csvfile.close()

print("\nTotal Files : "+str(line_count-1))
print("Files not found with name : "+str(no_results))
print("Script completed !!!")

