#!/usr/bin/env python
# coding: utf-8

# In[19]:


from __future__ import print_function

import os
import json
import sys
import re

# This is not required if you've installed pycparser into
# your site-packages/ with setup.py
#
sys.path.extend(['.', '..'])

from pycparser import parse_file, c_ast
from pycparser.plyparser import Coord


RE_CHILD_ARRAY = re.compile(r'(.*)\[(.*)\]')
RE_INTERNAL_ATTR = re.compile('__.*__')


class CJsonError(Exception):
    pass


def memodict(fn):
    """ Fast memoization decorator for a function taking a single argument """
    class memodict(dict):
        def __missing__(self, key):
            ret = self[key] = fn(key)
            return ret
    return memodict().__getitem__


@memodict
def child_attrs_of(klass):
    """
    Given a Node class, get a set of child attrs.
    Memoized to avoid highly repetitive string manipulation
    """
    non_child_attrs = set(klass.attr_names)
    all_attrs = set([i for i in klass.__slots__ if not RE_INTERNAL_ATTR.match(i)])
    return all_attrs - non_child_attrs


def to_dict(node):
    """ Recursively convert an ast into dict representation. """
    klass = node.__class__

    result = {}

    # Metadata
    result['_nodetype'] = klass.__name__

    # Local node attributes
    for attr in klass.attr_names:
        result[attr] = getattr(node, attr)

    # Coord object
    if node.coord:
        result['coord'] = str(node.coord)
    else:
        result['coord'] = None

    # Child attributes
    for child_name, child in node.children():
        # Child strings are either simple (e.g. 'value') or arrays (e.g. 'block_items[1]')
        match = RE_CHILD_ARRAY.match(child_name)
        if match:
            array_name, array_index = match.groups()
            array_index = int(array_index)
            # arrays come in order, so we verify and append.
            result[array_name] = result.get(array_name, [])
            if array_index != len(result[array_name]):
                raise CJsonError('Internal ast error. Array {} out of order. '
                    'Expected index {}, got {}'.format(
                    array_name, len(result[array_name]), array_index))
            result[array_name].append(to_dict(child))
        else:
            result[child_name] = to_dict(child)

    # Any child attributes that were missing need "None" values in the json.
    for child_attr in child_attrs_of(klass):
        if child_attr not in result:
            result[child_attr] = None

    return result


def to_json(node, **kwargs):
    """ Convert ast node to json string """
    return json.dumps(to_dict(node), **kwargs)


def file_to_dict(filename):
    """ Load C file into dict representation of ast """
    ast = parse_file(filename, use_cpp=True,
            cpp_path='clang',
            cpp_args=['-E', r'-IC:/Users/shiko/AppData/Local/Packages/PythonSoftwareFoundation.Python.3.9_qbz5n2kfra8p0/LocalCache/local-packages/Python39/site-packages/pycparser/utils/fake_libc_include'])
    return to_dict(ast)


def file_to_json(filename, **kwargs):
    """ Load C file into json string representation of ast """
    ast = parse_file(filename, use_cpp=True,
            cpp_path='clang',
            cpp_args=['-E', r'-IC:/Users/shiko/AppData/Local/Packages/PythonSoftwareFoundation.Python.3.9_qbz5n2kfra8p0/LocalCache/local-packages/Python39/site-packages/pycparser/utils/fake_libc_include'])
    return to_json(ast, **kwargs)


def _parse_coord(coord_str):
    """ Parse coord string (file:line[:column]) into Coord object. """
    if coord_str is None:
        return None

    vals = coord_str.split(':')
    vals.extend([None] * 3)
    filename, line, column = vals[:3]
    return Coord(filename, line, column)


def _convert_to_obj(value):
    """
    Convert an object in the dict representation into an object.
    Note: Mutually recursive with from_dict.
    """
    value_type = type(value)
    if value_type == dict:
        return from_dict(value)
    elif value_type == list:
        return [_convert_to_obj(item) for item in value]
    else:
        # String
        return value


def from_dict(node_dict):
    """ Recursively build an ast from dict representation """
    class_name = node_dict.pop('_nodetype')

    klass = getattr(c_ast, class_name)

    # Create a new dict containing the key-value pairs which we can pass
    # to node constructors.
    objs = {}
    for key, value in node_dict.items():
        if key == 'coord':
            objs[key] = _parse_coord(value)
        else:
            objs[key] = _convert_to_obj(value)

    # Use keyword parameters, which works thanks to beautifully consistent
    # ast Node initializers.
    return klass(**objs)


def from_json(ast_json):
    """ Build an ast from json string representation """
    return from_dict(json.loads(ast_json))


# In[20]:


maxCoord = 0
vulnerabilityCount = 0
openFile = None


# In[21]:


def createVarDict(blockItems, varDict):
    if type(blockItems) == list:
        for blockDict in blockItems:
            if type(blockDict) == dict:
                varDict.update(analyzeASTDict(blockDict, varDict))
                if blockDict['_nodetype'] == 'If' or blockDict['_nodetype'] == 'While': #TODO:Test for loops
                    varDict.update(createVarDict(blockDict, varDict))
    elif type(blockItems) == dict:
        varDict.update(analyzeASTDict(blockItems, varDict))
        for key in blockItems:
            if type(blockItems[key]) == dict:
                varDict.update(analyzeASTDict(blockItems[key], varDict))
                varDict.update(createVarDict(blockItems[key], varDict))
    return varDict
def analyzeASTDict(blockDict, varDict):
    if blockDict['_nodetype'] == 'Decl':
        typeString = ""
        if 'names' in blockDict['type']['type']: #ie. is not a pointer
            for varType in blockDict['type']['type']['names']:
                typeString += varType
            varDict[blockDict['name']] = {'type': typeString, 'length': 'null', 'value': 'null'}
            leftVal = 'null'
            rightVal = 'null'
            temp = 'null'
            if 'init' in blockDict and bool(blockDict['init']):
                init = blockDict['init']
                if init['_nodetype'] == 'Constant':
                    varDict[blockDict['name']]['value'] = init['value']
                elif init['_nodetype'] == 'ID':
                    for var in varDict.keys():
                        if var == init['name'] and varDict[var]['value'] != 'null':
                            varDict[blockDict['name']]['value'] = varDict[var]['value']
                elif init['_nodetype'] == 'BinaryOp':
                    if init['left']['_nodetype'] == 'Constant' and init['right']['_nodetype'] == 'Constant':
                        _locals = locals()
                        exec("temp = " + varDict[blockDict['name']]['type'] + "(" + init['left']['value'] + init['op'] + init['right']['value'] + ")")
                        varDict[blockDict['name']]['value'] = _locals['temp']
                    elif init['left']['_nodetype'] == 'ID' or init['right']['_nodetype'] == 'ID':
                        if init['left']['_nodetype'] == 'ID':
                            for var in varDict.keys():
                                if var == init['left']['name']:
                                    leftVal = varDict[var]['value']
                        elif init['left']['_nodetype'] == 'Constant':
                            leftVal = init['left']['value']
                        
                        if init['right']['_nodetype'] == 'ID':
                            for var in varDict.keys():
                                if var == init['right']['name']:
                                    rightVal = varDict[var]['value']
                        elif init['right']['_nodetype'] == 'Constant':
                            rightVal = init['right']['value']
                        if leftVal == 'null' or rightVal == 'null':
                            varDict[blockDict['name']]['value'] = 'null'
                        else:
                            _locals = locals()
                            exec("temp = " + varDict[blockDict['name']]['type'] + "(" + rightVal + init['op'] + leftVal + ")")
                            varDict[blockDict['name']]['value'] = _locals['temp']
        elif 'type' in blockDict['type']['type']: # ie. is a pointer
            for varType in blockDict['type']['type']['type']['names']:
                typeString += varType
            varDict[blockDict['name']] = {'type': typeString + '*', 'length': 'null', 'value': 'null'}
            if 'dim' in blockDict['type'] and bool(blockDict['type']['dim']):
                dimDict = blockDict['type']['dim']

                if dimDict['_nodetype'] == 'Constant':
                    varDict[blockDict['name']]['length'] = dimDict['value']
                elif dimDict['_nodetype'] == 'ID':
                    for key in varDict:
                        if key == dimDict['name']:
                            if varDict[key]['value'] != 'null' and varDict[key]['value'].isnumeric():
                                    varDict[blockDict['name']]['length'] = varDict[key]['value']
                                    #No break here since local variables are priortized over globals
                elif dimDict['_nodetype'] == 'BinaryOp':
                            result = evaluateBinaryOp(dimDict, varDict)
                            if result != 'null':
                                varDict[blockDict['name']]['length'] = int(result)
            elif 'init' in blockDict and bool(blockDict['init']):
                initDict = blockDict['init']
                
                if initDict['_nodetype'] == 'Constant' and initDict['type'] == 'string':
                    val = initDict['value'][1:-1] #In pycparser format is "STRING", but want STRING
                    varDict[blockDict['name']]['length'] = len(val)
                elif initDict['_nodetype'] == 'InitList':
                    varDict[blockDict['name']]['value'] = list()
                    for item in initDict['exprs']:
                        if item['_nodetype'] == 'Constant':
                            varDict[blockDict['name']]['value'].append(item['value'])
                        elif item['_nodetype'] == 'ID':
                            temp = 'null'
                            for var in varDict:
                                if var == item['name']:
                                    temp = varDict[var]
                            varDict[blockDict['name']]['value'].append(temp)
                        elif item['_nodetype'] == 'BinaryOp':
                             varDict[blockDict['name']]['value'].append(evaluateBinaryOp(item, varDict))
                    varDict[blockDict['name']]['length'] = len(varDict[blockDict['name']]['value'])

    elif blockDict['_nodetype'] == 'Assignment':
        temp = 'null'
        _locals = locals()
        varName = blockDict['lvalue']['name']
        assignDict = blockDict['rvalue']

        if type(varName) == dict:
            varName = varName['name']
        if varDict[varName]['type'][-1] != '*': #ie. not a pointer:
            if assignDict['_nodetype'] == 'Constant':
                if blockDict['op'] == '=':
                    varDict[varName]['value'] = assignDict['value']
                else:
                    if varDict[varName]['value'].isnumeric():
                        exec("temp = " + 'float' + '(' + varDict[varName]['value'] + ')')
                    else:
                        exec("temp = " + varDict[varName]['value'] + ')')
                    temp = _locals['temp']
                    if assignDict['value'].isnumeric():
                        exec("temp" + blockDict['op'] + 'float' + '(' + assignDict['value'] + ')')
                    else:
                        exec("temp" + blockDict['op'] + assignDict['type'] + '(' + assignDict['value'] + ')')

                    checkOverflowAssignmentOp(_locals['temp'], varDict[varName]['type'], blockDict['coord'])
                    varDict[varName]['value'] = _locals['temp']
            elif assignDict['_nodetype'] == 'ID':
                for var in varDict.keys():
                    if var == assignDict['name'] and varDict[var]['value'] != 'null':
                        if blockDict['op'] == '=':
                            varDict[varName]['value'] = varDict[var]['value']
                        else:
                            exec("temp = " + varDict[varName]['value'])
                            exec("temp " + blockDict['op'] + varDict[var]['value'])
                            checkOverflowAssignmentOp(_locals['temp'], varDict[varName]['type'], blockDict['coord'])
                            varDict[varName]['value'] = _locals['temp']
            elif assignDict['_nodetype'] == 'BinaryOp':
                if assignDict['left']['_nodetype'] == 'Constant' and assignDict['right']['_nodetype'] == 'Constant':
                    if blockDict['op'] == '=':
                        exec("temp = " + varDict[varName]['type'] + "(" + assignDict['left']['value'] + assignDict['op'] + assignDict['right']['value'] + ")")
                        varDict[varName]['value'] = _locals['temp']
                    else:
                        exec("temp = " + varDict[varName]['value'])
                        exec("temp " + blockDict['op'] + varDict[varName]['type'] + "(" + assignDict['left']['value'] + assignDict['op'] + assignDict['right']['value'] + ")")
                        checkOverflowAssignmentOp(_locals['temp'], varDict[varName]['type'], blockDict['coord'])
                        varDict[varName]['value'] = _locals['temp']
                elif assignDict['left']['_nodetype'] == 'ID' or assignDict['right']['_nodetype'] == 'ID':
                    leftVal = 'null'
                    rightVal = 'null'
                    temp = 'null'

                    if assignDict['left']['_nodetype'] == 'ID':
                        for var in varDict.keys():
                            if var == assignDict['left']['name']:
                                leftVal = varDict[var]['value']
                    elif assignDict['left']['_nodetype'] == 'Constant':
                        leftVal = assignDict['left']['value']
                    
                    if assignDict['right']['_nodetype'] == 'ID':
                        for var in varDict.keys():
                            if var == assignDict['right']['name']:
                                rightVal = varDict[var]['value']
                    elif assignDict['right']['_nodetype'] == 'Constant':
                        rightVal = assignDict['right']['value']
                    
                    if leftVal == 'null' or rightVal == 'null':
                        varDict[varName]['value'] = 'null'
                    else:
                        if blockDict['op'] == '=':
                            exec("temp = " + 'float' + "(" + str(rightVal) + assignDict['op'] + str(leftVal) + ")")
                            checkOverflowAssignmentOp(_locals['temp'], varDict[varName]['type'], blockDict['coord'])
                            varDict[varName]['value'] = _locals['temp']
                        else:
                            exec("temp = " + varDict[varName]['value'])
                            exec("temp" + blockDict['op'] + varDict[varName]['type'] + "(" + str(rightVal) + assignDict['op'] + str(leftVal) + ")")
                            checkOverflowAssignmentOp(_locals['temp'], varDict[varName]['type'], blockDict['coord'])
                            varDict[varName]['value'] = _locals['temp']
            elif blockDict['_nodetype'] == 'UnaryOp':
                varName = blockDict['expr']['name']
                if varDict[varName]['value'] != 'null':
                    if blockDict['op'] == 'p++' or blockDict['op'] == '++p':
                        if varDict[varName]['type'] != 'double' or varDict[varName]['type'] != 'float':
                            varDict[varName]['value'] = int(varDict[varName]['value'])
                        else:
                            varDict[varName]['value'] = float(varDict[varName]['value'])
                        varDict[varName]['value'] += 1
                        checkOverflowAssignmentOp(varDict[varName]['value'], varDict[varName]['type'], blockDict['coord'])
                    elif blockDict['op'] == 'p--' or blockDict['op'] == '++p':
                        if varDict[varName]['type'] != 'double' or varDict[varName]['type'] != 'float':
                            varDict[varName]['value'] = int(varDict[varName]['value'])
                        else:
                            varDict[varName]['value'] = float(varDict[varName]['value'])
                        varDict[varName]['value'] -= 1
                        checkOverflowAssignmentOp(varDict[varName]['value'], varDict[varName]['type'], blockDict['coord'])
        elif varDict[varName]['type'][-1] == '*': #ie. is a pointer
            if assignDict['_nodetype'] == 'UnaryOp':
                if assignDict['op'] == '&' or assignDict['op'] == '*':
                    if 'subscript' in assignDict['expr']:
                        if assignDict['expr']['subscript']['_nodetype'] == 'Constant':
                            varDict[varName]['length'] = varDict[assignDict['expr']['name']['name']]['length'] - int(assignDict['expr']['subscript']['value'])
                        elif assignDict['expr']['subscript']['_nodetype'] == 'ID':
                            for key in varDict:
                                if key == assignDict['expr']['subscript']['name']:
                                    val = int(varDict[key]['value'])
                                    varDict[varName]['length'] = varDict[assignDict['expr']['name']['name']]['length'] - val
                        elif assignDict['expr']['subscript']['_nodetype'] == 'BinaryOp':
                            result = evaluateBinaryOp(assignDict['expr']['subscript'], varDict)
                            if result != 'null':
                                varDict[varName]['length'] = int(result)
                    else:
                        varDict[varName]['length'] = varDict[assignDict['expr']['name']]['length']
            elif assignDict['_nodetype'] == 'Constant':
                val = initDict['value'][1:-1] #In pycparser format is "STRING", but want STRING
                varDict[blockDict['name']]['length'] = len(val)
    return varDict


# In[22]:


def evaluateBinaryOp(json_object, varDict):
    if json_object['_nodetype'] == 'BinaryOp':
        leftDict = json_object['left']
        rightDict = json_object['right']
        op = json_object['op']
        leftVal = 'null'
        rightVal = 'null'

        if leftDict['_nodetype'] == 'Constant':
            leftVal = leftDict['value']
        elif leftDict['_nodetype'] == 'ID' and leftDict['name'] in varDict:
            leftVal = varDict[leftDict['name']]['value']
        elif leftDict['_nodetype'] == 'BinaryOp':
            leftVal = evaluateBinaryOp(leftDict, varDict)
        
        if rightDict['_nodetype'] == 'Constant':
            rightVal = rightDict['value']
        elif rightDict['_nodetype'] == 'ID' and rightDict['name'] in varDict:
            rightVal = varDict[rightDict['name']]['value']
        elif rightDict['_nodetype'] == 'BinaryOp':
            rightVal = evaluateBinaryOp(rightDict, varDict)
       
        if leftVal != 'null' and rightVal != 'null':
            temp = 'null'
            _locals = locals()
            exec("temp = " + "float(" + leftVal + ')' + op + "float(" + rightVal + ')')
            result = _locals['temp']
            return result
        else:
            return 'null'


# In[23]:


def detectRisks(json_object, varDict, lineDict):
    global maxCoord
    global vulnerabilityCount
    if type(json_object) == dict:
        for key in json_object:
            if key == '_nodetype' and json_object[key] != 'FileAST':
                match = re.search('(:[0-9]+:)', json_object['coord'])
                if match != None:
                    lineNum = int(match.group().strip(':'))
                    if lineNum >= maxCoord and type(json_object) == dict:
                        maxCoord = lineNum
                        varDict.update(createVarDict(json_object, varDict))
                if json_object[key] == 'FuncDef':
                    #Create paramList
                    paramList = list()
                    if json_object['decl']['type']['args'] != None:
                        for param in json_object['decl']['type']['args']['params']:
                            paramList.append(param['name'])
                elif json_object[key] == 'FuncCall':
                    bufferMoveOrCopyFunctionsList = ['memmove', 'memcpy', 'strcat', 'strncat', 'strcpy', 'strncpy']
                    for function in bufferMoveOrCopyFunctionsList:
                        if json_object['name']['name'] == function:
                            argsList = json_object['args']['exprs']

                            if argsList[len(argsList) - 1]['_nodetype'] == 'Constant':
                                if int(varDict[argsList[0]['name']]['length']) < int(argsList[len(argsList) - 1]['value']):
                                    match = re.search('(:[0-9]+:)', json_object['args']['coord'])
                                    lineNum = match.string.strip(':')
                                    print('Possible vunerability \"CWE-120: Buffer Copy without Checking Size of Input\" detected. (Case: Destination buffer is smaller than incoming changes.)')
                                    print('Revise line ' + str(lineNum))
                                    print()
                                    line = openFile.readlines()[maxCoord - 1]
                                    vunerableCount += 1
                                    lineDict['vul' + str(vunerableCount)] = dict()
                                    lineDict['vul' + str(vunerableCount)]['line'] = line.strip()
                                    lineDict = createCodeSnippet(lineDict)
                            elif argsList[len(argsList) - 1]['_nodetype'] == 'ID':
                                overflowed = False
                                for var in varDict:
                                    if var == argsList[len(argsList) - 1]['name']:
                                        if (varDict[var]['value'] != 'null' and int(varDict[var]['value']) > int(varDict[argsList[0]['name']]['length'])) or (varDict[var]['length'] != 'null' and int(varDict[var]['length']) > int(varDict[argsList[0]['name']]['length'])):
                                            overflowed = True
                                        else:
                                            overflowed = False

                                if overflowed == True:
                                    match = re.search('(:[0-9]+:)', json_object['args']['coord'])
                                    lineNum = match.string.strip(':')
                                    print('Possible vunerability \"CWE-120: Buffer Copy without Checking Size of Input\" detected. (Case: Destination buffer is smaller than incoming changes.)')
                                    print('Revise line ' + str(lineNum))
                                    print()
                                    line = openFile.readlines()[maxCoord - 1]
                                    vunerableCount += 1
                                    lineDict['vul' + str(vunerableCount)] = dict()
                                    lineDict['vul' + str(vunerableCount)]['line'] = line.strip()
                                    lineDict = createCodeSnippet(lineDict)
                            elif argsList[len(argsList) - 1]['_nodetype'] == 'BinaryOp':
                                result = evaluateBinaryOp(json_object, varDict)
                    userMutableFunctionsList = ['gets', 'getopt', 'getopt_long', 'scanf']
                    for function in userMutableFunctionsList:
                        overflowed = False
                        if function != 'scanf':
                            if json_object['name']['name'] == function:
                                overflowed = True
                        else:
                            match = re.search(function, json_object['name']['name'])
                            if match != None:
                                argsList = json_object['args']['exprs']
                                for arg in argsList:
                                    if arg['_nodetype'] == 'Constant' and '%s' in arg['value']:
                                        overflowed = True
                        
                        if overflowed == True:
                            match = re.search('(:[0-9]+:)', json_object['coord'])
                            lineNum = match.string.strip(':')
                            print('Possible vunerability \"CWE-120: Buffer Copy without Checking Size of Input\" detected. (Case: User can pass large buffer.)')
                            print('Revise line ' + str(lineNum))
                            print()
                            line = openFile.readlines()[maxCoord - 1]
                            vunerableCount += 1
                            lineDict['vul' + str(vunerableCount)] = dict()
                            lineDict['vul' + str(vunerableCount)]['line'] = line.strip()
                            lineDict = createCodeSnippet(lineDict)
            detectRisks(json_object[key], varDict, lineDict)
    elif type(json_object) == list:
        for item in json_object:
            detectRisks(item, varDict, lineDict)
    return lineDict

# In[24]:


def createCodeSnippet(lineDict):
    global maxCoord
    global vulnerabilityCount
    global openFile
    lines = openFile.readLines()
    for vul in lineDict:
        if maxCoord > 1 and maxCoord + 2 < len(lines):
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord - 2] + lines[maxCoord - 1] + lines[maxCoord] + lines[maxCoord + 1] + lines[maxCoord + 2]
        elif maxCoord > 1 and maxCoord + 1 < len(lines):
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord - 2] + lines[maxCoord - 1] + lines[maxCoord] + lines[maxCoord + 1]
        elif maxCoord > 0 and maxCoord + 2 < len(lines):
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord - 1] + lines[maxCoord] + lines[maxCoord + 1] + lines[maxCoord + 2]
        elif maxCoord > 0 and maxCoord + 1 < len(lines):
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord - 1] + lines[maxCoord] + lines[maxCoord + 1]
        elif maxCoord == 0 and maxCoord + 2 < len(lines):
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord] + lines[maxCoord + 1] + lines[maxCoord + 2]
        elif maxCoord == 0 and maxCoord + 1 < len(lines):
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord] + lines[maxCoord + 1]
        elif maxCoord == len(lines) - 1 and len(lines) > 2:
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord - 2] + lines[maxCoord - 1] + lines[maxCoord]
        elif maxCoord == len(lines) - 1 and len(lines) > 1:
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord - 1] + lines[maxCoord]
        elif maxCoord == len(lines) - 1:
            lineDict['vul' + str(vunerableCount)]['snippet'] = lines[maxCoord]
    return lineDict

# def removeHeadersAndComments(text):
#     def replacer(match):
#         s = match.group(0).strip(' ')
#         if s.startswith('#') or s.startswith('/') or s.startswith('#'):
#             return ""
#         else:
#             return s
#     pattern = re.compile(
#         r'.*#.*|//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
#         re.DOTALL | re.MULTILINE
#     )
#     return re.sub(pattern, replacer, text)

def beginCheck(file):
    global maxCoord
    global vulnerabilityCount
    global openFile
    # with open(file.name) as f:
    #     lines = f.readlines()
    #     os.chmod(file.name, 0o777)
    #     with open(file.name, 'w+') as f:
    #         for line in lines:
    #             f.write(removeHeadersAndComments(line))
    openFile = open(file.name)
    ast_dict = file_to_dict(file.name)
    ast = from_dict(ast_dict)
    jsonString = to_json(ast,indent=4)
    jsonObject = json.loads(jsonString)
    #outfile.write(fileName + "\n")
    #json.dump(jsonObject, outfile, indent=4)
    #outfile.write("\n\n")
    #print(fileName)
    maxCoord = 0
    vulnerabilityCount = 0
    varDict = {}
    lineDict = {}
    lineDict = detectRisks(jsonObject, varDict, lineDict)
    print("----------------------------------------------------------------------------------------")
    return lineDict

