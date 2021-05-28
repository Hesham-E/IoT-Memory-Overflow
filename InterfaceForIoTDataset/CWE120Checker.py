import os
import re

functionsREGEX = ["(scanf[ ]*\([ ]*\"%s\")|(scanf\(.{1,}[,][ ]*\".*%s.*\")",
                  "(gets[ ]*\()", 
                  "(strcpy[ ]*\(.{1,}[,].{1,}\))", 
                  "(memcpy[ ]*\(.{1,}[,].{1,}\))", 
                  "(memmove[ ]*\(.{1,}[,].{1,}\))", 
                  "(memset[ ]*\(.{1,}[,].{1,}\))", 
                  "(strncat[ ]*\(.{1,}[,].{1,}[,].{1,}\))", 
                  "(strcat[ ]*\(.{1,}[,].{1,}\))", 
                  "(strncpy[ ]*\(.{1,}[,].{1,}[,].{1,}\))", 
                  "((sprintf)|(vsprintf)|(swprintf)|(vswprintf)|(_stprintf)|(_vstprintf))([ ]*\(.{1,}[,])",
                  "(MultiByteToWideChar[ ]*\(.{1,}[,].{1,}[,].{1,}[,].{1,}[,].{1,}[,].{1,}\))",
                  "(strtrns[ ]*\(.{1,}[,].{1,}[,].{1,}[,].{1,}\))", 
                  "(realpath[ ]*\(.{1,}[,].{1,}\))", 
                  "((getopt)|(getopt_long))([ ]*\(.{1,}[,].{1,}[,].{1,}\))", 
                  "(getwd[ ]*\(.{1,}[,].{1,}\))", 
                  "((getchar)|(fgetc)|(getc)|(fread)|(_gettc))([ ]*\(.*\))"]
                  
def findFunctionCall (line):
    for functionREGEX in functionsREGEX:
        functionREGEX = '(?<!\/\/)' + functionREGEX #Expression to ensure that line is not a comment 
        lineNoWhiteSpace = "".join(line.split()) #Remove spaces since negative lookbehind pattern needs a definitive width
        match = re.search(functionREGEX, lineNoWhiteSpace)
        if match:
            coord = match.span()
            if coord[0] > line.find('//'): #Explicitly check that the match is before the comment
                return True
    return False

def findFunctionCall (file):
    lineDict = dict()
    print('Checking for \"CWE-120: Buffer Copy without Checking Size of Input\" in file ',file.name)
    print('-----------------------------------------------------------------------------\n')
    lines = file.readlines()
    vunerableCount = 0
    inComment = False

    for i in range(len(lines)):
        line = lines[i]
        if line.find('*/') != -1:
            inComment = False
        if line.find('/*') != -1:
            commentEnd = line.find('*/')
            inComment = True if commentEnd  == -1 else False
            if inComment:
                line = line[:line.find('/*')]
            else:
                line = line[:line.find('/*')] + line[commentEnd:]
        if inComment == False:
            for functionREGEX in functionsREGEX:
                functionREGEX = '(?<!\/\/)' + functionREGEX #Expression to ensure that line is not a comment 
                lineNoWhiteSpace = "".join(line.split()) #Remove spaces since negative lookbehind pattern needs a definitive width
                match = re.search(functionREGEX, lineNoWhiteSpace)
                if match:
                    coord = match.span()
                    if(line.find('//') != -1): #Explicitly check that the match is before the comment
                        line = line[:line.find('//')]
                    vunerableCount += 1
                    lineDict['vul' + str(vunerableCount)] = dict()
                    lineDict['vul' + str(vunerableCount)]['line'] = line.strip()
                    print('Possible vulnerability : \"CWE-120: Buffer Copy without Checking Size of Input\"')
                    print('Need inspection at Line #',i + 1,' :',line.strip())
                    print()
                    if i > 1 and i + 2 < len(lines):
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i - 2] + lines[i - 1] + lines[i] + lines[i + 1] + lines[i + 2]
                    elif i > 1 and i + 1 < len(lines):
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i - 2] + lines[i - 1] + lines[i] + lines[i + 1]
                    elif i > 0 and i + 2 < len(lines):
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i - 1] + lines[i] + lines[i + 1] + lines[i + 2]
                    elif i > 0 and i + 1 < len(lines):
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i - 1] + lines[i] + lines[i + 1]
                    elif i == 0 and i + 2 < len(lines):
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i] + lines[i + 1] + lines[i + 2]
                    elif i == 0 and i + 1 < len(lines):
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i] + lines[i + 1]
                    elif i == len(lines) - 1 and len(lines) > 2:
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i - 2] + lines[i - 1] + lines[i]
                    elif i == len(lines) - 1 and len(lines) > 1:
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i - 1] + lines[i]
                    elif i == len(lines) - 1:
                        lineDict['vul' + str(vunerableCount)]['snippet'] = lines[i]

    if vunerableCount == 0:
        print('No \"CWE-120: Buffer Copy without Checking Size of Input\" found in file: ',file.name)
    else:
        print(vunerableCount,'possible \"CWE-120: Buffer Copy without Checking Size of Input\" found in file: ',file.name)
    print('-----------------------------------------------------------------------------\n')
    return lineDict