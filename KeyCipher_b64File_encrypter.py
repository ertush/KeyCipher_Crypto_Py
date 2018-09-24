#!/usr/bin/python2.7

import sys,string,os
import random as rd
import base64 as bs

MODE = 1
KEY = 2
STRING = 3
PATHTOSAVE = 4
KEYMODE = 5

LETTERS = string.ascii_letters+string.digits+string.punctuation #string.printable.replace(' \t\n\r'+'\x0b\x0c', '') #string.ascii_letters+string.digits+string.punctuation  #string.letters+string.digits+string.punctuation

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
                #print "{}".format(encStrings[len(encStrings) - 1])
                return (encStrings[len(encStrings) - 1])
                exit()
        else:
            try:
                enstr = encryptDecryptString(mode,key,str,keyMode)
                print ("{}").format(enstr)
            except RuntimeError as e:
                print ("[!] Encountered : {}\n[*] Avoid using single line ('-n') encryption with key of > 2 digits").format(e)
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
                print ("[!]Unable to encrypt key size to large")
                exit()
                      
        else:
            trans += byte
                

    if mode == "encrypt":
        return trans

    if mode == "decrypt":
        return trans
          
    #pyperclip.copy(trans.lower())

def encodedecodeFile(mode,key,file,savePath,keyMode):
    with open(file) as f:
        filename = savePath #raw_input("\n[*]Enter path to save the (encrypted\decrypted) file : ")
        print(filename)
        #if filename == "":
            #filename="C:\Users\Dell\Desktop\enc.txt"

        if '~/' in filename:
            filename = filename.replace('~/','')
        elif '\\' in  filename:
            filename = filename.replace('\\',"\\")
        #print ("\n{}:").format(filename.upper())
        #print ({}).format(('='*len(filename)))
        for line in f.readlines():
            if keyMode == 'encrypt':
                line = bs.b64encode(line)
            elif keyMode == 'decrypt':    
                line = bs.b64decode(line)            
            encline = encryptDecryptString(mode,key,line,keyMode)

            with open(filename,'a') as encf:
                last1Byte = encline[len(encline)-1:len(encline)] 
                encf.write(encline.replace(last1Byte, ''))
                #encf.write(encline)
                
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
            print ("[!] Key String Entered cannot be used as a Cipher Key\n")
            exit()
    keys = ""
    return keys.join(keylist)
 
        
        
if __name__ == "__main__":
    if len(sys.argv) != 6:
        print ("\nUsage: KeyCipher [OPTIONS] [<int> | <string> KEY] [PATH] [DESTINATION PATH] -m\n")
        print ("OPTIONS\t\tDEFINATION\n")
        print ("=======\t\t==========\n")
        print ("--encrypt\tMode for encryption\n--decrypt\tMode for decryption\n--help\t\tDisplay help message\n--keyMode\tMultiple key encryption <'-m'>\n")

        exit()
    if sys.argv[MODE] == '--encrypt':
        try:
            if os.path.exists(sys.argv[STRING]) == True:
                encodedecodeFile("encrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[PATHTOSAVE],sys.argv[KEYMODE])
            
            encryptDecryptString("encrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[KEYMODE])


        except ValueError as e:
            print ("[!] Encountered :{}\n[*] Please Use a key of type <int>").format(e)
            exit()
        
    elif sys.argv[MODE] == '--decrypt':
        if os.path.exists(sys.argv[STRING]) == True:
            encodedecodeFile("decrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[PATHTOSAVE],sys.argv[KEYMODE])
        encryptDecryptString("decrypt",KeyString(sys.argv[KEY]),sys.argv[STRING],sys.argv[KEYMODE])
    else:
        print ("\nUsage: KeyCipher [OPTIONS] [<int> | <string> KEY] [PATH] [DESTINATION PATH] -m\n")
        print ("OPTIONS\t\tDEFINATION\n")
        print ("=======\t\t==========\n")
        print ("--encrypt\tMode for encryption\n--decrypt\tMode for decryption\n--help\t\tDisplay help message\n--KeyMode\tMultiple Key encryption <'-m'>\n") 
        exit()
        
        


