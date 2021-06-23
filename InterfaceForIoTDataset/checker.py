from CWE120Checker import findFunctionCall
from CWE120ASTChecker import beginCheck
from pycparser.plyparser import ParseError
import io
import re
import os

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
        if fileNameKeyword in fileName.lower()[-2:]: #exclude .cpp files since .c in .cpp
            return True
    return False

def removeHeaders(text):
    def replacer(match):
        s = match.group(0).strip(' ')
        if s.startswith('#include') or s.startswith('#import'):
            return ""
        else:
            return s
    pattern = re.compile(
        r'.*#.*',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


def comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return ""
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)

def CheckerProcessor(filepath, writer):
    try:
        fileInInspection = io.open(filepath, 'r', encoding='utf-8',
                                errors='ignore')
        fileNameParts = filepath.split('/')
        year = fileNameParts[2]
        githubID = fileNameParts[3]
        totalVulnerabilityFound = 0
        #fileNameKeyWords = ['.c', '.h', '.cpp']
        fileNameKeyWords = ['.c', '.h']

        if NeedInspection(filepath, fileNameKeyWords):
            print('Checking vulnerabilities in ', filepath)
            print('-----------------------------------------------------------------------------\n')
            for vulnerability in vulnerabilities:
                if vulnerability["CWE"] == 120:
                    print('Checking for \"' + vulnerability["FullName"] + '\" in file ', filepath)
                    print('-----------------------------------------------------------------------------\n')
                    try:
                        lineDict = beginCheck(fileInInspection)
                    except Exception as c:
                        try:
                            print("Exception Occured. Removing comments.", c)
                            with open(fileInInspection.name) as f:
                                lines = f.readlines()
                                os.chmod(fileInInspection.name, 0o777)
                                with open(fileInInspection.name, 'w+') as f:
                                    for line in lines:
                                        f.write(comment_remover(line))
                            lineDict = beginCheck(fileInInspection)
                        except Exception as h:
                            try:
                                print("Exception Occured. Removing #include statments.", h)
                                with open(fileInInspection.name) as f:
                                    lines = f.readlines()
                                    os.chmod(fileInInspection.name, 0o777)
                                    with open(fileInInspection.name, 'w+') as f:
                                        for line in lines:
                                            f.write(removeHeaders(line))
                                lineDict = beginCheck(fileInInspection)
                            except Exception as e:
                                print("Exception Occured. Switching to detection with regular expressions.", e)
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
    
