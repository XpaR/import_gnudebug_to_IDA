#!/usr/bin/python3
import sys
#import idaapi
#import idautils
#import idc
from elftools.elf.elffile import ELFFile

SYMBOLS_FILE = "symbolsfile.txt"

def enable_python_disable_IDC():
    load_and_run_plugin("python", 3)
    
def enable_IDC_disable_python():
    load_and_run_plugin("python", 4)

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
    
def get_gnu_debugdata(filename):
    print("Trying to fetch debug data from .gnu_debugdata section of {f}".format(f=filename))
    with open(filename, "rb") as f1:
        elffile = ELFFile(f1)
        section = elffile.get_section_by_name(".gnu_debugdata")
        if section is None:
            print("Could not find the .gnu_debugdata section, exiting...")
        else:
            for subsection in section.elffile.iter_sections():
                print(subsection.name)
                print(subsection.data())
                
            
            return section.data() # This gives a compressed ELF file with all the symbols in it. ELF binary with only the symbol & headers.

def main():
    for filename in sys.argv[1:]:
        get_gnu_debugdata(filename)
    #do_rename(read_symbols_from_text())
    
if __name__ == "__main__":
    main()