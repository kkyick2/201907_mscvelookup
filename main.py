#!/usr/bin/env python
# import pkg
import csv
import sys
import pprint
# import 3rd parties pkg
import requests

matchword = [
	'Windows 7 for 32-bit Systems Service Pack 1',
	'Windows Server 2012 R2 (Server Core installation)'
]
infilename = 'march_cve.txt'
outfilename = 'output.csv'


# backwards compatibility for python3 and python2 csv writer
def open_csv(filename, mode='w'):
	"""
	Open a csv file in proper mode depending on Python verion.
	with open (outfilename, 'wb') as outF: 					# this code is for python2
	with open (outfilename, 'w', newline='') as outF:	 	# this code is for python3
	"""
	return open(filename, mode=mode + 'b') if sys.version_info[0] == 2 else open(filename, mode=mode, newline='')


# open output CSV
with open_csv(outfilename, 'w') as outF:
	writer = csv.writer(outF)
	print('=========================================================================')
	print('==================== Begin Script  ======================================')
	print('=========================================================================')
	count = 0
	count1 = 0 # count for matched product
	count2 = 0 # count for product not in use
	# open CVE list
	with open(infilename, 'r') as inF:
		for cve in inF:
			cve = cve.strip(' \n\t')
			cve_url = "https://portal.msrc.microsoft.com/api/security-guidance/en-US/CVE/"+cve
			print('=== Search web: {}'.format(cve_url))
			response = requests.get(cve_url)
			cve_dict = response.json()
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
						itemstring = string1 + '\n' + string2 + '\n' + string3 + '\n'
						printflag = True
					else:
						continue
					outstring = outstring + itemstring
			if printflag is True:
				writer.writerow([cve, product, outstring])
				# print('=== Matched product')
				count1 += 1
			else:
				writer.writerow([cve, 'N/A', 'Affected product not in use'])
				print('=== Affected product not in use')
				count2 += 1

			# End of this CVE link
			count += 1
			print('**********************')

	print('=========================================================================')
	print('=== Summary:')
	print('=== Total CVE searched    : {}'.format(count))
	print('=== No of Matched CVE     : {}'.format(count1))
	print('=== No of not Affected CVE: {}'.format(count2))
