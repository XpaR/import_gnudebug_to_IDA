#!/usr/bin/python2
import sys
import idaapi
import idautils
import idc

SYMBOLS_FILE = "symbolsfile.txt"
 
if __name__ == "__main__":
    main()

 
#if(len(sys.argv) < 2):
#    print("usage: {0} <input file>".format(sys.argv[0]))
#    exit(1)
 
#input file must contain only the <segment:offset> [<number>] <function name> <some text>(ex: 0000:0013 [1] _main)
 
def _fix_line(strn):
    result=[]
    for index,char in enumerate(strn):
        if(char == '[' or char == ']'):
            result.append(index)
        if(len(result) == 2):
            break
    new_str=strn[:strn.find("Type: ")]
    return (new_str[:result[0]] + new_str[result[1]+1:])

def read_symbols_from_text():
    file=open(SYMBOLS_FILE,"r+")
    org_file=file.read()
 
    file.close()
    del file
    
    spl_file=org_file.split("\n")
    result=[]
 
    for x in spl_file:
        if(x == ''):
            continue
        else:
            result.append(_fix_line(x))
            
    print('\n'.join(result))
    
    return '\n'.join(result)

"""
Purpose: Rename the symbols
Parameters:
    l -> the filename to take the data from.
"""
def do_rename(l):
    splitted = l.split()
    straddr = splitted[0]
    strname = splitted[1].replace("\r", "").replace("\n", "")

    if straddr.find(":") != -1: #assuming form segment:offset
        #removing segment, offset should be unique, if it isn't so, we should handle it differently
        straddr = straddr.split(":")[1]

    eaaddr = int(straddr, 16)
    idc.MakeCode(eaaddr)
    idc.MakeFunction(eaaddr)
    idc.MakeNameEx(int(straddr, 16), strname, idc.SN_NOWARN)

def main():
    do_rename(read_symbols_from_text())