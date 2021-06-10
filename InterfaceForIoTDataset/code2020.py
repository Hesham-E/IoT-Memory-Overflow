#!/usr/bin/env python
# coding: utf-8

# In[1]:


import json
import csv
import checker


# In[2]:


def getExtensionList():
    extensionList = {
    "code":".h .c .cpp"
    }
    for key in extensionList.keys():
        extensionList[key] = extensionList[key].split()
    return extensionList


# In[3]:


def extenstionChecker(filename,extensionList):
    for key in extensionList.keys():
        currentList = extensionList[key]
        for extension in currentList:
            if filename.lower().endswith(extension.lower()):
                return True
        
    return False


# In[4]:


import os
import time
import io
startTime = time.time()
extensionList = getExtensionList()
totalFile= 0
totalNonCheckableFile = 0
totalVulnerabilityFound = 0 
totalVulnerableFile = 0
with io.open('vulnerability.csv', 'w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerow(["GithubID","Year","FullPath","Codesnippet","CWE","isTrueVulnerable", "Codesnippet5"])
    for dirpath, dirs, files in os.walk("../../Dataset Download/2020"):
        for filename in files:
            totalFile+=1
            fname = os.path.join(dirpath,filename)
            if extenstionChecker(filename,extensionList) == False or '/.git' in fname or '/env/' in fname:
                totalNonCheckableFile +=1
                # print('Not suitable for checking: ',fname)
                continue
            noOfVulnerability = checker.CheckerProcessor(fname,writer)
            totalVulnerabilityFound += noOfVulnerability
            if noOfVulnerability!=0:
                totalVulnerableFile+=1    
print("Total Repo: ",1612)        
print("Total File: ",totalFile)
print("Total non checkable file: ",totalNonCheckableFile)
print("Total checkable file: ",totalFile-totalNonCheckableFile)
print("Total vulnerable file: ",totalVulnerableFile)
print("Total vulnerability found: ",totalVulnerabilityFound)
print("Total time taken: ",time.time() - startTime)


# In[ ]:




