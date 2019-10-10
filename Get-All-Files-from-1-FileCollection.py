#Developer - K.Janarthanan
#Date - 20/9/2019
#Purpose - 
#   To webscrap "Hybrid Analysis" website; 
#   Get all Files from a particular file collection;

from urllib.request import Request, urlopen
import requests
from bs4 import BeautifulSoup

software_url ="https://www.hybrid-analysis.com/file-collection/5d6a8fa0038838bf675a8d5a"

req = Request(software_url , headers={'User-Agent': 'Mozilla/5.0'})

page = urlopen(req).read()

soup= BeautifulSoup(page, 'html.parser')


attack = soup.find('tbody', class_='rowlink')

count=0

for rows in attack.find_all('tr'):
    for columns in rows.find_all('td'):
        
        count+=1

        #Info on column 1
        if (count==1):
            
            
            try:
                link_url=columns.find('a')
                print("\nURL is : https://www.hybrid-analysis.com"+link_url['href'])
            except:
                print ("unable to access element")

        #Info on column 2
        if (count==2):
            
            try:
                sha_256=columns.find('span')
                print("\ncool is : "+sha_256['data-title'])
            except:
                print ("unable to access element")

            
        #Info on column 6
        if (count==6):
            try:
                attack_info=columns.get_text().strip()
                print ("Threat Level : "+attack_info+"\n")
            except:
                print ("unable to access element")
               
            
        if (count==7):
            count=0