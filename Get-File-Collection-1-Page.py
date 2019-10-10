#Developer - K.Janarthanan
#Date - 20/9/2019
#Purpose - 
#   To webscrap "Hybrid Analysis" website; 
#   Get all File collections from 1 page only;
 
from urllib.request import Request, urlopen
import requests
from bs4 import BeautifulSoup

software_url ="https://www.hybrid-analysis.com/file-collections?page=1"

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
            print("\nURL is : https://www.hybrid-analysis.com"+link_url['href'])
            
        #Info on column 4
        if (count==5):
            attack_info=columns.get_text().strip()
            print ("Threat Level of file collection : "+attack_info+"\n")
            
            
        if (count==6):
            count=0