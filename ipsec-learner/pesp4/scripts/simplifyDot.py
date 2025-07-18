#!/usr/bin/env python
import os
import argparse
            
def simplfy(dot_file):
    f = open(dot_file, "r")
    lines = f.readlines()
    f.close()
    
    dot = ''
    transs = []
    for line in lines:
        if ('->' not in line) or ('start' in line):
            dot += line
        else:
            trans = line.split('[')[0]
            if trans in transs:
                continue
            transs.append(trans)
            new_line = trans + '[label="'
            for l in lines:
                if trans in l:
                    new_line += (l.split('label="')[1].split('"]')[0] + '\n')
            new_line += '"];\n'
            dot += new_line
            
    f = open("simplfy_" + str(dot_file), "w+")
    f.write(dot)
    f.close()
            
def remove_start(dot_file):
    fi = open(dot_file, 'r')
    lines = fi.readlines()
    fi.close()
    
    os.remove(dot_file)
    fo = open(dot_file, 'w+')
    for line in lines:
        if 'start' in line:
            continue
        fo.write(line)
    fo.close()
        

# Parse the input arguments
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--dot_file',type=str,required=True)
    args = parser.parse_args()
    simplfy(args.dot_file)
