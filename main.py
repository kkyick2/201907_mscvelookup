import requests
import pprint
import time
import csv

matchword = ['Windows 7 for 32-bit Systems Service Pack 1','Windows Server 2012 R2 (Server Core installation)']

#open output CSV
with open ('output.csv', mode='wb') as outF:
	writer = csv.writer(outF)
	# open CVE list
	with open('march_cve.txt','r') as inF:
		for cve in inF:
			print('*******start *****************')
			cve = cve.strip(' \n\t')
			cve_url = "https://portal.msrc.microsoft.com/api/security-guidance/en-US/CVE/"+cve
			print(cve_url)
			response = requests.get(cve_url)
			cve_dict = response.json()
			#print('***************************')
			#print(type(cve_dict[u'affectedProducts']))
			print('***************************')
			#print(len(cve_dict[u'affectedProducts']))
			
			outstring = ''
			itemstring = ''
			printflag = False
			# loop the table in the CVE web
			for i in range(len(cve_dict[u'affectedProducts'])):
				product = cve_dict[u'affectedProducts'][i][u'name']
				for matchedOS in matchword:
					if matchedOS in product:
						string1 = (cve_dict[u'affectedProducts'][i][u'name'])
						string2 = (cve_dict[u'affectedProducts'][i][u'downloadTitle1']+":"+ cve_dict[u'affectedProducts'][i][u'articleTitle1'])
						string3 = (cve_dict[u'affectedProducts'][i][u'downloadTitle2']+":"+ cve_dict[u'affectedProducts'][i][u'articleTitle2'])
						itemstring = string1 +'\n' + string2 +'\n' + string3 +'\n'
						printflag = True
					else:
						continue
					outstring = outstring + itemstring
			if printflag is True:
				writer.writerow([cve,product,outstring])
			else:
				writer.writerow([cve,'N/A','Affected product not used'])
				
			#time.sleep(1)
			print('********* end *************')
	
	
	