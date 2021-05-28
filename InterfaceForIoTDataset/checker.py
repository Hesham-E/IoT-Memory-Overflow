from CWE120Checker import findFunctionCall
import io

vulnerabilities = [
    {
        "FullName": "CWE-120: Buffer Copy without Checking Size of Input",
        "CWE": 120,
        "FileNameKeywords": [
            ".c",
            ".cpp",
            ".h"
        ]
    },
    {
        "FullName": "CWE-190: Integer Overflow or Wraparound",
        "CWE": 190,
        "FileNameKeywords": [
                ".c",
                ".cpp",
                ".h"
        ]
    }
]


def NeedInspection(fileName, fileNameKeywords):
    for fileNameKeyword in fileNameKeywords:
        if fileNameKeyword in fileName.lower():
            return True
    return False

def CheckerProcessor(filepath, writer):
    try:
        fileInInspection = io.open(filepath, 'r', encoding='utf-8',
                                errors='ignore')
        fileNameParts = filepath.split('/')
        year = fileNameParts[2]
        githubID = fileNameParts[3]
        totalVulnerabilityFound = 0
        fileNameKeyWords = ['.c', '.h', '.cpp']

        if NeedInspection(filepath, fileNameKeyWords):
            print('Checking vulnerabilities in ', filepath)
            print('-----------------------------------------------------------------------------\n')
            for vulnerability in vulnerabilities:
                if vulnerability["CWE"] == 120:
                    print('Checking for \"' + vulnerability["FullName"] + '\" in file ', filepath)
                    print('-----------------------------------------------------------------------------\n')
                    lineDict = findFunctionCall(fileInInspection)
                    if bool(lineDict):
                        print('Possible vulnerability : \"' + vulnerability["FullName"] + '\"')
                        for vul in lineDict:
                            print('Need inspection at :',lineDict[vul]['line'].strip())
                            print()
                            totalVulnerabilityFound += 1
                            writer.writerow([githubID, year, filepath,
                                            lineDict[vul]['line'].strip(), vulnerability["CWE"], 1, lineDict[vul]['snippet']])
                # if vulnerability["CWE"] == 190:
                #     print('Checking for \"' + vulnerability["FullName"] + '\" in file ', filepath)
                #     print('-----------------------------------------------------------------------------\n')

        if totalVulnerabilityFound == 0:
            print('No vulnerability found in file: ', filepath)
        else:
            print(totalVulnerabilityFound,
                    ' vulnerabilities found in file: ', filepath)
        print('-----------------------------------------------------------------------------\n')
        return totalVulnerabilityFound
    except FileNotFoundError:
        print('excepted')
        return 0
    
