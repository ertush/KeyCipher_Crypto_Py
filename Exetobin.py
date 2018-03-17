#!/usr/bin/python
#import sys
#INPUT, OUTPUT = 1, 2

#def ExetoTxt(indir, outdir):
#	with open(indir, "rb") as file:
#		while(file.readline() != None):
#			for line in file.readlines():
#				bin=open(outdir, "wb")
				#bin.write(line)
#				print "--> "+line
				
#	bin.close()
#	file.close()
	
import base64, sys

chunksize = 6144
linelength = 80

INPUT, OUTPUT = 1, 2
def ExetoTxt(indir, outdir):
	with open(indir,'rb') as inf, open(outdir,'w') as outf:
		#outf.write('program_data = """')

		while True:
			progdata = inf.read(chunksize)
			if len(progdata):
				progdata = progdata.encode("base64")
				outf.writelines(progdata[i:i+linelength] for i in range(0, len(progdata), linelength))
			else:
				break

		#outf.write('""".decode("base64")')
	
	
		
if __name__ == "__main__":
	ExetoTxt(sys.argv[INPUT], sys.argv[OUTPUT])
	
		

