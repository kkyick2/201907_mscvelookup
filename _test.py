import requests
import pprint

cve_url = "https://portal.msrc.microsoft.com/api/security-guidance/en-US/CVE/CVE-2019-0611"
response = requests.get(cve_url)
cve_dict = response.json()
#print('***************************')
#print('***************************')
#print(cve_dict)
#print('***************************')
#pprint.pprint(cve_dict)
#print('***************************')
print(type(cve_dict[u'affectedProducts']))
print(len(cve_dict[u'affectedProducts']))

matchword = 'Windows 7 for 32-bit Systems Service Pack 1'

for i in range(len(cve_dict[u'affectedProducts'])):
	product = cve_dict[u'affectedProducts'][i][u'name']

	print('***************************')
	if matchword in product:
		print 'matched!!'
		pprint.pprint(cve_dict[u'affectedProducts'][i][u'downloadTitle1']+":"+ cve_dict[u'affectedProducts'][i][u'articleTitle1'])
		pprint.pprint(cve_dict[u'affectedProducts'][i][u'downloadTitle2']+":"+ cve_dict[u'affectedProducts'][i][u'articleTitle2'])
		##pprint.pprint(cve_dict[u'affectedProducts'][i][u'articleTitle1'])
		##pprint.pprint(cve_dict[u'affectedProducts'][i][u'articleTitle2'])
		##pprint.pprint(cve_dict[u'affectedProducts'][i][u'downloadTitle1'])
		##pprint.pprint(cve_dict[u'affectedProducts'][i][u'downloadTitle2'])
	else:
		pprint.pprint(cve_dict[u'affectedProducts'][i][u'name'])

	
	
	