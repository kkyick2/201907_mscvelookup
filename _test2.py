import requests
import pprint
import time

matchword = 'Windows 7 for 32-bit Systems Service Pack 1'

with open('march_cve.txt','r') as f:
	for cve in f:
		print('*******start *****************')
		cve_url = "https://portal.msrc.microsoft.com/api/security-guidance/en-US/CVE/"+cve.strip(' \n\t')
		print(cve_url)
		response = requests.get(cve_url)
		cve_dict = response.json()
		#print('***************************')
		#print(type(cve_dict[u'affectedProducts']))
		print('***************************')
		#print(len(cve_dict[u'affectedProducts']))

		for i in range(len(cve_dict[u'affectedProducts'])):
			product = cve_dict[u'affectedProducts'][i][u'name']
			if matchword in product:
				print(cve_dict[u'affectedProducts'][i][u'name'])
				print(cve_dict[u'affectedProducts'][i][u'downloadTitle1']+":"+ cve_dict[u'affectedProducts'][i][u'articleTitle1'])
				print(cve_dict[u'affectedProducts'][i][u'downloadTitle2']+":"+ cve_dict[u'affectedProducts'][i][u'articleTitle2'])
			else:
				continue
		time.sleep(1)
		print('********* end *************')
	
	
	