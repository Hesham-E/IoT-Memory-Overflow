#!/usr/bin/env python
# coding: utf-8

# In[47]:


import os

from __future__ import print_function

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
            cpp_args=['-E', r'-Iutils/fake_libc_include'])
    return to_dict(ast)


def file_to_json(filename, **kwargs):
    """ Load C file into json string representation of ast """
    ast = parse_file(filename, use_cpp=True,
            cpp_path='clang',
            cpp_args=['-E', r'-Iutils/fake_libc_include'])
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


# In[48]:


folderPath = './Testdata/'
fileList = os.listdir(folderPath)


# In[49]:


outfile = open('result.txt', "w")
for fileName in fileList:
    ast_dict = file_to_dict(folderPath + fileName)
    ast = from_dict(ast_dict)
    jsonString = to_json(ast,indent=4)
    jsonObject = json.loads(jsonString)
    outfile.write(fileName + "\n")
    json.dump(jsonObject, outfile, indent=4)
    outfile.write("\n\n")
    # print(fileName)
    # print(json.dumps(jsonObject, indent = 4))
    # print("----------------------------------------------------------------------------------------")


# In[50]:


"""
AST Start
Go into ext
Go into decl
Go into body
Go into block items
for every Decl node in block itmes
    Get variable type
    If the variable is initialized
        Go into initialization
        If initalized to a constant
            get the constant
        Else if initialized to a variable and the variable is not a function argumaent
            get the variable from the dict
        Else if initialzied to an expression
            if all operands are constants
                evaluate the expression
            else if some of the operands are variables
                if some variables are unknown
                    set the value to 'unknown'
                else
                    get the variable values
                    evaluate the expression
            else
                set the value to 'unknown'
for every Assignment node in block items
    If Assignment['lvalue']['name'] in dict and dict[Assignment['lvalue']['name']]['type'] == 'int'
    Go into assignment
        If assigned to a constant
            get the constant
        Else if assigned to a variable and the variable is not a function argumaent
            get the variable from the dict
        Else if assigned to an expression
            if all operands are constants
                evaluate the expression
            else if some of the operands are variables
                if some variables are unknown
                    set the value to 'unknown'
                else
                    get the variable values
                    evaluate the expression
            else
                set the value to 'unknown'
"""

def createVarDict(blockItems):
    varDict = dict()
    if type(blockItems) == list:
        for blockDict in blockItems:
            if blockDict['_nodetype'] == 'Decl':
                typeString = ""
                for varType in blockDict['type']['type']['names']:
                    typeString += varType

                varDict[blockDict['name']] = {'type': typeString, 'value': 'null'}
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
                                        leftVal = varDict[var]['value']
                            elif init['right']['_nodetype'] == 'Constant':
                                leftVal = init['right']['value']
                            
                            if leftVal == 'null' or rightVal == 'null':
                                varDict[blockDict['name']]['value'] = 'null'
                            else:
                                _locals = locals()
                                exec("temp = " + varDict[blockDict['name']]['type'] + "(" + rightVal + init['op'] + leftVal + ")")
                                varDict[blockDict['name']]['value'] = _locals['temp']

            elif blockDict['_nodetype'] == 'Assignment':
                temp = 'null'
                _locals = locals()
                varName = blockDict['lvalue']['name']
                assignDict = blockDict['rvalue']

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
            elif blockDict['_nodetype'] == 'If' or blockDict['_nodetype'] == 'While': #Test for loops
                varDict.update(createVarDict(blockDict))
    return varDict


# In[51]:


def detectRisks(json_object, paramList, varDict, funcDict):
    if type(json_object) == dict:
        for key in json_object:
            if key == '_nodetype' and json_object[key] != 'FileAST':
                if json_object[key] == 'FuncDef':
                    #Create paramList
                    paramList = list()
                    if json_object['decl']['type']['args'] != None:
                        for param in json_object['decl']['type']['args']['params']:
                            paramList.append(param['name'])

                    #Create varDict
                    varDict = createVarDict(json_object['body']['block_items'])
                    #Add function return type to funcDict
                    funcDict.update({json_object['decl']['name']: json_object['decl']['type']['type']['type']['names'][0]})
                elif json_object[key] == 'Decl' and 'init' in json_object and bool(json_object['init']) and 'op' in json_object['init']:
                    operation = json_object['init']['op']
                    if operation == '+' or operation == '-' or operation == '*':
                        if ('name' in json_object['init']['left'] and json_object['init']['left']['name'] in paramList or 'name' in json_object['init']['right'] and json_object['init']['right']['name'] in paramList) and json_object['type']['type']['names'][0] == 'int':
                            match = re.search('(:[0-9]+:)', json_object['init']['coord'])
                            lineNum = match.string.strip(':')
                            print('Possible vunerability "CWE-190 Integer Overflow or Wraparound" detected. (Case: Function parameters used in initialization)')
                            print('Revise line ' + str(lineNum))
                            print()
                
                #Case for 'a = b - c' where a is an int and b or c are function arguments
                elif json_object[key] == 'Assignment' and 'rvalue' in json_object and 'op' in json_object['rvalue'] and (json_object['rvalue']['op'] == '+' or json_object['rvalue']['op'] == '-' or json_object['rvalue']['op'] == '*') and 'name' in json_object['rvalue']['left'] and 'name' in json_object['rvalue']['right'] and (json_object['rvalue']['left']['name'] in paramList or json_object['rvalue']['right']['name'] in paramList):
                    flaggedVar = json_object['lvalue']['name']
                    if flaggedVar in varDict.keys() and varDict[flaggedVar]['type'] == 'int':
                        match = re.search('(:[0-9]+:)', json_object['coord'])
                        lineNum = match.string.strip(':')
                        print('Possible vunerability "CWE-190 Integer Overflow or Wraparound" detected. (Case: Function parameters used in assignment)')
                        print('Revise line ' + str(lineNum))
                        print()
                elif json_object[key] == 'Return' and list(funcDict.values())[-1] == 'int':
                    #Case for 'return b - c' where return is an int, where b or c are function arguments
                    if 'op' in json_object['expr'] and (json_object['expr']['op'] == '+' or json_object['expr']['op'] == '-' or json_object['expr']['op'] == '*') and (json_object['expr']['left']['name'] in paramList or json_object['expr']['right']['name'] in paramList):
                        match = re.search('(:[0-9]+:)', json_object['coord'])
                        lineNum = match.string.strip(':')
                        print('Possible vunerability "CWE-190 Integer Overflow or Wraparound" detected. (Case: Function parameters returned)')
                        print('Revise line ' + str(lineNum))
                        print()
                    #Case for 'return a' where return is an int and 'a' is a function argument
                    elif 'name' in json_object['expr'] and json_object['expr']['name'] in paramList:
                        match = re.search('(:[0-9]+:)', json_object['coord'])
                        lineNum = match.string.strip(':')
                        print('Possible vunerability "CWE-190 Integer Overflow or Wraparound" detected. (Case: Function parameters returned)')
                        print('Revise line ' + str(lineNum))
                        print()

                #Case for 'b op c > MAX or b op c < MIN' where b, c are integers
                elif json_object[key] == 'BinaryOp' and (json_object['op'] == '+' or json_object['op'] == '-' or json_object['op'] == '*'):
                    leftVal = None
                    rightVal = None
                    tempVal = None
                    _locals = locals()

                    if json_object['left']['_nodetype'] == 'ID' and json_object['left']['name'] in varDict:
                        leftVal = {'type': varDict[json_object['left']['name']]['type'], 'value': 0}
                        exec("tempVal = " + 'float' + "(" + str(varDict[json_object['left']['name']]['value']) + ")", _locals)
                        leftVal['value'] = _locals['tempVal']
                    elif json_object['left']['_nodetype'] == 'Constant':
                        leftVal = {'type': json_object['left']['type'], 'value': 0}
                        exec("tempVal = " + 'float' + "(" + json_object['left']['value'] + ")", _locals)
                        leftVal['value'] = _locals['tempVal']
                    if json_object['right']['_nodetype'] == 'ID' and json_object['right']['name'] in varDict:
                        rightVal = {'type': varDict[json_object['right']['name']]['type'], 'value': 0}
                        exec("tempVal = " + 'float' + "(" + varDict[json_object['right']['name']]['value'] + ")", _locals)
                        rightVal['value'] = _locals['tempVal']
                    elif json_object['right']['_nodetype'] == 'Constant' :
                        rightVal = {'type': json_object['right']['type'], 'value': 0}
                        exec("tempVal = " + 'float' + "(" + json_object['right']['value'] + ")", _locals)
                        rightVal['value'] = _locals['tempVal']
                   
                    if bool(leftVal) and bool(rightVal):
                        overflowed = checkOverflowBinaryOp(leftVal, rightVal, json_object)
                        if overflowed:
                            match = re.search('(:[0-9]+:)', json_object['coord'])
                            lineNum = match.string.strip(':')
                            print('Possible vunerability "CWE-190 Integer Overflow or Wraparound" detected. (Case: Binary Operation resulting in overflow)')
                            print('Revise line ' + str(lineNum))
                            print()
            detectRisks(json_object[key], paramList, varDict, funcDict)
    
    elif type(json_object) == list:
        for item in json_object:
            detectRisks(item, paramList, varDict, funcDict)

def checkOverflowBinaryOp(leftVal, rightVal, json_object):
    # char	1 byte	-128 to 127 or 0 to 255
    # unsigned char	1 byte	0 to 255
    # signed char	1 byte	-128 to 127
    # int	2 or 4 bytes	-32,768 to 32,767 or -2,147,483,648 to 2,147,483,647
    # unsigned int	2 or 4 bytes	0 to 65,535 or 0 to 4294967295
    # short	2 bytes	-32768 to 32767
    # unsigned short	2 bytes	0 to 65535
    # long	8 bytes or (4bytes for 32 bit OS)	-9223372036854775808 to 9223372036854775807
    # unsigned long	8 bytes	0 to 18446744073709551615
    overflowed = False
    if leftVal['type'] == 'unsignedlong' or rightVal['type'] == 'unsignedlong':
        MAX = 18446744073709551615
        MIN = 0
    elif leftVal['type'] == 'long' or rightVal['type'] == 'long':
        MAX = 9223372036854775807
        MIN = -9223372036854775808
    elif leftVal['type'] == 'unsignedshort' or rightVal['type'] == 'unsignedshort':
        MAX = 65535
        MIN = 0
    elif leftVal['type'] == 'short' or rightVal['type'] == 'short':
        MAX = 32767
        MIN = -32768
    elif leftVal['type'] == 'unsignedint' or rightVal['type'] == 'unsignedint':
        MAX = 4294967295
        MIN = 0
    elif leftVal['type'] == 'int' or rightVal['type'] == 'int':
        MAX = 2147483647
        MIN = -2147483648
    elif leftVal['type'] == 'signedchar' or rightVal['type'] == 'signedchar':
        MAX = 127
        MIN = -128
    elif leftVal['type'] == 'unsignedchar' or rightVal['type'] == 'unsignedchar':
        MAX = 255
        MIN = 0
    elif leftVal['type'] == 'char' or rightVal['type'] == 'char':
        MAX = 255
        MIN = -128
    else:
        return False

    if json_object['op'] == '+':
        result = leftVal['value'] + rightVal['value']

        if leftVal['value'] > 0 and rightVal['value'] > 0 and result > MAX:
            overflowed = True
        elif leftVal['value'] < 0 and rightVal['value'] < 0 and result < MIN:
            overflowed = True
        elif leftVal['value'] < 0 and rightVal['value'] > 0 or leftVal['value'] > 0 and rightVal['value'] < 0 and result < MIN:
            overflowed = True
    elif json_object['op'] == '-':
        result = leftVal['value'] - rightVal['value']

        if leftVal['value'] > 0 and rightVal['value'] < 0 and result > MAX:
            overflowed = True
        elif leftVal['value'] < 0 and rightVal['value'] < 0 and result > MAX:
            overflowed = True
        elif leftVal['value'] < 0 and rightVal['value'] > 0 and result < MIN:
            overflowed = True
    elif json_object['op'] == '*':
        result = leftVal['value'] * rightVal['value']
    
        if result > MAX or result < MIN:
            overflowed = True
    return overflowed

def checkOverflowAssignmentOp(value, valType, coord):
    if valType == 'unsignedlong':
        MAX = 18446744073709551615
        MIN = 0
    elif valType == 'long':
        MAX = 9223372036854775807
        MIN = -9223372036854775808
    elif valType == 'unsignedshort':
        MAX = 65535
        MIN = 0
    elif valType == 'short':
        MAX = 32767
        MIN = -32768
    elif valType == 'unsignedint':
        MAX = 4294967295
        MIN = 0
    elif valType == 'int':
        MAX = 2147483647
        MIN = -2147483648
    elif valType == 'signedchar':
        MAX = 127
        MIN = -128
    elif valType == 'unsignedchar':
        MAX = 255
        MIN = 0
    elif valType == 'char':
        MAX = 255
        MIN = -128
    else:
        return None
    
    if value > MAX or value < MIN:
        match = re.search('(:[0-9]+:)', coord)
        lineNum = match.string.strip(':')
        print('Possible vunerability "CWE-190 Integer Overflow or Wraparound" detected. (Case: Assignment operation resulting in overflow)')
        print('Revise line ' + str(lineNum))
        print()

        


# In[52]:


for fileName in fileList:
    ast_dict = file_to_dict(folderPath + fileName)
    ast = from_dict(ast_dict)
    jsonString = to_json(ast,indent=4)
    jsonObject = json.loads(jsonString)
    print(fileName)
    detectRisks(jsonObject, list(), dict(), dict())
    print("----------------------------------------------------------------------------------------")


# In[53]:


"""
AST Start
Laterally find ext
Laterally find body
Go into body
Laterally find block_items
Go into block_items
    Find index with "init": not NULL
        If ("name": is a var int) AND (init['op'] is +,-,*) AND ((init['left']['_nodetype'] is 'ID') OR (init['right']['_nodetype'] is 'ID'))
            Flag the line
    Find index with "_nodetype": Assignment
        If (lvalue['name'] is a var int) AND (rvalue['op'] is +,-,*) AND ((left['_nodetype'] is 'ID') OR (right['_nodetype'] is 'ID'))
            Flag the line

"""

"""
AST Start
Laterally find ext
Laterally find body
Go into body
Laterally find block_items
Go into block_items
Go through indicies
    If '_nodetype' is 'Assignment' AND 'rvalue'['op'] is +,-,* AND 'rvalue'['left']['_nodetype'] is 'ID' OR 'rvalue'['right']['_nodetype'] is 'ID'
        Store block_items[index]['lvalue']['name'] into var
        goto block_items[0] and go through indicies
            If '_nodetype' is 'Decl' AND 'name' is var AND 'type'['type']['names'][0] is int
                Flag the line
"""

"""
AST Start
Go into ext
Go into decl
Go into body
Go into block items
for every Decl node in block itmes
    Get variable type
    If the variable is initialized
        Go into initialization
        If initalized to a constant
            get the constant
        Else if initialized to a variable and the variable is not a function argumaent
            get the variable from the dict
        Else if initialzied to an expression
            if all operands are constants
                evaluate the expression
            else if some of the operands are variables
                if some variables are unknown
                    set the value to 'unknown'
                else
                    get the variable values
                    evaluate the expression
            else
                set the value to 'unknown'
for every Assignment node in block items
    If Assignment['lvalue']['name'] in dict and dict[Assignment['lvalue']['name']]['type'] == 'int'
    Go into assignment
        If assigned to a constant
            get the constant
        Else if assigned to a variable and the variable is not a function argumaent
            get the variable from the dict
        Else if assigned to an expression
            if all operands are constants
                evaluate the expression
            else if some of the operands are variables
                if some variables are unknown
                    set the value to 'unknown'
                else
                    get the variable values
                    evaluate the expression
            else
                set the value to 'unknown'
"""

