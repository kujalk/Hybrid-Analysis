#Developer - K.Janarthanan
#Date - 20/9/2019
#Purpose - 
#   To webscrap "Hybrid Analysis" website; 
#   Get all File collection that are malicious; 
#   Get SHA256 files that are only malicious from the collection;  
#   Store SHA256 only in CSV

from urllib.request import Request, urlopen
import requests
from bs4 import BeautifulSoup
import csv

all_files=0
malicious=0
mal_file=[]
for i in range(39):

    software_url ="https://www.hybrid-analysis.com/file-collections?page="+(str(i+1))

    print ("Working on page : "+str(i+1))

    req = Request(software_url , headers={'User-Agent': 'Mozilla/5.0'})

    page = urlopen(req).read()

    soup= BeautifulSoup(page, 'html.parser')


    attack = soup.find('tbody', class_='rowlink')

    count=0
    

    for rows in attack.find_all('tr'):
        
        for columns in rows.find_all('td'):
            
            count+=1
            
            #Info on column 2
            if (count==2):
                
                link_url=columns.find('a')
                link="https://www.hybrid-analysis.com"+link_url['href']
                print("\nURL is : "+link)
                
            #Info on column 4
            if (count==5):
                attack_info=columns.get_text().strip()
                print ("Threat Level : "+attack_info+"\n")

                if(attack_info=="malicious"):


                    req2 = Request(link , headers={'User-Agent': 'Mozilla/5.0'})

                    page2 = urlopen(req2).read()

                    soup= BeautifulSoup(page2, 'html.parser')

                    #print(str(page2))

                    attack = soup.find('tbody', class_='rowlink')

                    n_count=0

                    for rows in attack.find_all('tr'):
                        for columns in rows.find_all('td'):
                            
                            n_count+=1

                            #Info on column 1
                            if (n_count==1):
                                try:
                                    link_url=columns.find('a')
                                    print("\nURL is : https://www.hybrid-analysis.com"+link_url['href'])
                                except:
                                    print ("unable to access element")

                            #Info on column 2
                            if (n_count==2):
                                
                                try:
                                    sha_256=columns.find('span')
                                    api_sha_256=sha_256['data-title']
                                    print("\ncool is : "+sha_256['data-title'])
                                except:
                                    print ("unable to access element")

                                
                            #Info on column 6
                            if (n_count==6):

                                try:
                                    attack_info=columns.get_text().strip()
                                    print ("Threat Level : "+attack_info+"\n")
                                    
                                    if (attack_info=="malicious"):
                                        #
                                        mal_file.append(api_sha_256)
                                        #
                                        print("calling API")
                                        malicious+=1
                                    all_files+=1
                                except:
                                    print ("unable to access element")
                                
                            if (n_count==7):
                                n_count=0
                
                
            if (count==6):
                count=0

print("Total files : "+str(all_files))
print("Total malicious files :  "+str(malicious))

for i in range(len(mal_file)):

     data=[[mal_file[i]]]
     csv_file="Get_Mal_file_Only.csv"

     # If python 3 , with open (csv_file,'a',newline='') as csvfile: 
     with open (csv_file,'a',newline='') as csvfile:
        writer=csv.writer(csvfile)
        writer.writerows(data)

csvfile.close()
