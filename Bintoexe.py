import base64, sys

chunksize = 6144
linelength = 80

INPUT, OUTPUT = 1, 2
def ExetoTxt(indir, outdir):
	with open(indir,'rb') as inf, open(outdir,'w') as outf:

		while True:
			progdata = inf.read(chunksize)
			if len(progdata):
				progdata =  decodebytes(progdata) #progdata.decode("base64")
				outf.writelines(progdata[i:i+linelength] for i in range(0, len(progdata), linelength))
			else:
				break
	
		
if __name__ == "__main__":
	ExetoTxt(sys.argv[INPUT], sys.argv[OUTPUT])
	

