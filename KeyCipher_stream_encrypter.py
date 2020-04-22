#!/usr/bin/python


#import pyperclip

import sys,string,os
import random as rd
import base64 as bs

STRING = 3
KEY = 2
MODE = 1
KEYMODE = 4

# Omitting some special chars that have a trouble with powershell
special_chars = ['\'','\"'] # Additional special chars ['(',')','{','}','$','`','&','%','#']

punctuation = string.punctuation

for char in special_chars:
    punctuation = punctuation.replace(char, '')

# Alphanumerals [a-z:A-Z:0-9:all_special_chars]
LETTERS = string.letters+string.digits+punctuation

def encryptDecryptString(mode,key,str,keyMode):
   
    strKey = key.__str__()
    if len(strKey) > 2:
        if keyMode == '-m':
            encStrings = []
            for num in key:
                i = 0
                key = int(num)
                keyMode = '-n'
                encstr = encryptDecryptString(mode,key,str,keyMode)
                str = encryptDecryptString(mode,key,encstr,keyMode)
                encStrings.append(str)

            if encStrings[len(encStrings) - 1]:
                print "{}".format(encStrings[len(encStrings) - 1])
                return (encStrings[len(encStrings) - 1])
                exit()
         
        else:
            try:
                enstr = encryptDecryptString(mode,key,str,keyMode)
                print "{}".format(enstr)
            except RuntimeError as e:
                print "[!] Encountered : {}\n[*] Avoid using single line ('-n') encryption with key of > 2 digits".format(e)
                exit()

    key = int(key)
    trans = ''
      
    for byte in str:
        if byte in LETTERS:
            num = LETTERS.find(byte)
            if mode == 'encrypt':
                num += key
            elif mode == 'decrypt':
                num -= key

            if num >= len(LETTERS):
                num -= len(LETTERS)
            elif num < 0:
                num = num + len(LETTERS)
            try: 
                trans += LETTERS[num]
            except IndexError:
                print "[!]Unable to encrypt key size to large"
                exit()
                      
        else:
            trans += byte
                

    if mode == "encrypt":
        return trans

    if mode == "decrypt":
        return trans
          
    

def encodedecodeFile(mode,key,file,keyMode):
    with open(file) as f:
        filename = raw_input("\n[*]Enter path to save the (encrypted\decrypted) file : ")
        if '~/' in filename:
            filename = filename.replace('~/','')
        elif '\\' in  filename:
            filename = filename.replace('\\',"\\")
        print "\n{}:".format(filename.upper())
        print "{}".format(('='*len(filename)))
        for line in f.readlines():
            if filename.endswith('.m4a') and keyMode == 'encrypt':
                line = bs.b64encode(line)
            elif filename.endswith('.m4a') and keyMode == 'decrypt':    
                line = bs.b64decode(line)            
            encline = encryptDecryptString(mode,key,line,keyMode)

            with open(filename,'a') as encf: 
                encf.write(encline)


def KeyString(key):
    key = key.__str__()
    keylist = []
    for char in key:  
        if char in LETTERS:
            posKey = LETTERS.find(char)
            if posKey <= 26: 
                CipherKey = posKey % 26 
            else:
                CipherKey = posKey % 26
            keylist.append(CipherKey.__str__())
        else:
            print "[!] Key String Entered cannot be used as a Cipher Key\n"
            exit()
    keys = ""
    return keys.join(keylist)
 
def usage():
    print "\nUsage: KeyCipher [OPTIONS] [<int> | <string> KEY] [STRING] -m\n"
    print "OPTIONS\t\tDEFINATION\n"
    print "=======\t\t==========\n"
    print "--encrypt\tMode for encryption\n--decrypt\tMode for decryption\n--help\t\tDisplay help message\n--keyMode\tMultiple key encryption <'-m'>\n"

        
if __name__ == "__main__":
    if len(sys.argv) != 5:
        usage() 
        exit()
    if sys.argv[MODE] == '--encrypt':
        try:
            if os.path.exists(sys.argv[STRING]) == True:
                encodedecodeFile("encrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[KEYMODE])
            
            encryptDecryptString("encrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[KEYMODE])


        except ValueError as e:
            print "[!] Encountered :{}\n[*] Please Use a key of type <int>".format(e)
            exit()
        
    elif sys.argv[MODE] == '--decrypt':
        if os.path.exists(sys.argv[STRING]) == True:
            encodedecodeFile("decrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[KEYMODE])
        encryptDecryptString("decrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[KEYMODE])
    else:
        usage() 
        exit()
        
        


