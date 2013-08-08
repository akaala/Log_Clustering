import re, math
from bitarray import bitarray
from time import clock
import mmh3
import gc
import os
import optparse
import zipfile
import tarfile
import sys

PER_MATCH=0.6
MAX_BITS=400

class SketchString():
    """
        """
    def __init__(self):
        """
            """
        
        ip_port = r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d+'
        ip = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        time = r'(\d{1,2}:\d{1,2}:\d{1,2}|T\d{1,2}:\d{1,2}:\d{1,2})'
        date = r'(((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sept|Oct|Nov|Dec|Sun|Mon|Tue|Wed|Thu|Fri|Sat)\s*\d+)|(\d{2,4}/\d{1,2}/\d{1,2})|(\d{2,4}-\d{1,2}-\d{1,2}))'
        url = r'(((http|https|ftp|sftp|pop|dns|whois|finger|daytime|nntp|tcp|udp)://[\w\.]+)|((\w+\.){2,}[a-zA-Z]+))'
        
        separator = r'[\s\[\]\(\)<>\;"\']'
        
        decimal_number = separator + r'\d+\.\d+' + separator
        integer_number = separator + r'\d+' + separator
        
        
        equals = r'=\s*\S+'
        quoted = r'(("[^"]*")|(\'[^\']*\'))'
        
        self.reg = re.compile('(?P<ip_port>%s)|(?P<ip>%s)|(?P<time>%s)|(?P<date>%s)|(?P<url>%s)|(?P<float>%s)|(?P<int>%s)|(?P<equals>%s)|(?P<quoted>%s)' %
                              (ip_port, ip, time, date, url, decimal_number, integer_number, equals, quoted))
        self.Words_Vector = []
        self.log=[]
        self.hashmap1=[]
        self.hashmap2=[]
        self.hashmap3=[]
        self.bl_bits=MAX_BITS

        self.bloom_vector=[]
    
    def replace(self, match):
        """
            """
        
        if match.group('ip_port'):
            return '__IP_AND_PORT__'
        elif match.group('ip'):
            return '__IP__'
        elif match.group('date'):
            return '__DATE__'
        elif match.group('url'):
            return '__URL__'
        elif match.group('time'):
            return ' __TIME__ '
        elif match.group('float'):
            m = match.group('float')
            return '__FLOAT__'
        elif match.group('int'):
            m = match.group('int')
            return m[0] + '__INT__' + m[-1]
        elif match.group('equals'):
            return '=__VAR__ '
        elif match.group('quoted'):
            return '"__VAR__"'

    def process(self, message):
        """
            """
        
        return self.reg.sub(self.replace, ' %s ' % message).strip()
    
    def getWordText(self,text):
        self.log = self.process(text)
        
        for word in self.log.split():
            self.Words_Vector.append(word)
    
    def displayWordVector(self):
        length=len(self.Words_Vector)
        print "ASCII vector array: ",  ", ".join(self.Words_Vector[i] for i in range(length))
    #for i in range(length):
    
    def Hashmap_WordVector(self,nbits):
        length=len(self.Words_Vector)
        self.bl_bits=nbits
        self.bloom_vector=self.bl_bits*bitarray('0')
        for i in range(length):
            self.hashmap1.append(mmh3.hash(self.Words_Vector[i]) % self.bl_bits )
            self.hashmap2.append(mmh3.hash(self.Words_Vector[i],self.hashmap1[i]) % self.bl_bits )
            self.hashmap3.append(mmh3.hash(self.Words_Vector[i],self.hashmap2[i]) % self.bl_bits )
            self.bloom_vector[self.hashmap1[i]]=1
            self.bloom_vector[self.hashmap2[i]]=1
            self.bloom_vector[self.hashmap3[i]]=1
    
    
    def display_hashmap_Vector(self):
        #self.Hashmap_WordVector(nbits)
        length=len(self.hashmap1)
        print "hashmap array 1: ",  ", ".join(str(self.hashmap1[i]) for i in range(length))
        print "hashmap array 2: ",  ", ".join(str(self.hashmap2[i]) for i in range(length))
        print "hashmap array 3: ",  ", ".join(str(self.hashmap3[i]) for i in range(length))
        #print "Bloom-filter", self.bloom_vector,
        #print "count one Bloom-filter",self.bloom_vector.count()
    
    def count_Word_Vector(self):
        #self.Hashmap_WordVector(nbits)
        return len(self.Words_Vector)
    
    def count_hashmap_Vector(self,nbits):
        self.bloom_vector=[]
        self.hashmap1=[]
        self.hashmap2=[]
        self.hashmap3=[]
        self.bl_bits=nbits
        self.Hashmap_WordVector(nbits)
        count_setbits=self.bloom_vector.count() #print "count one Bloom-filter"
        #print "Bloom-filter", self.bloom_vector
        #self.display_hashmap_Vector()
        #print self.bl_bits
        return  count_setbits

    def Diff_bits_signature(self,other):
        XOR=(self.bloom_vector ^ other.bloom_vector)
        #print "Bloom-filter", self.bloom_vector ^ other.bloom_vector,"(XOR)",
        return XOR,XOR.count()
        
    def Common_bits_signature(self,other):
        AND=(self.bloom_vector & other.bloom_vector)
        #print "Bloom-filter", self.bloom_vector & other.bloom_vector ,"(AND)",
        return AND,AND.count()
    
    def Imp_bits_signature(self,other):
        OR=(self.bloom_vector | other.bloom_vector)
        #print "Bloom-filter", self.bloom_vector | other.bloom_vector ,"(OR)",
        return OR,OR.count()






def numberOfSetBits(i):
    i = i - ((i >> 1) & 0x55555555)
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333)
    return (((i + (i >> 4) & 0xF0F0F0F) * 0x1010101) & 0xffffffff) >> 24



def _parse_args():
    """parses the command line arguments"""
    usage = "Usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage)
    
    parser.add_option("-p", "--path", dest="path",
                      help="path to the directory where log files reside",
                      metavar="PATH")

    parser.add_option("-M", "--PER_MATCH", dest="PER_MATCH",
                          help="Percentage for matching making log clusters",
                          metavar="PER_MATCH")
    
    options, args = parser.parse_args()
    
    return options

def get_all_files(log_dir_path):
    """returns all the files inside the log directory"""
    if os.path.isfile(log_dir_path):
        return [log_dir_path]
    
    all_files = []
    for dirpath, dirs, files in os.walk(log_dir_path):
        for file in files:
            if file.startswith('.'):
                continue
            all_files.append(dirpath+'/'+file)

    return all_files

def get_file_size(filepath):
    """returns the size of the file in bytes"""
    return os.path.getsize(filepath)

def read_log_file(fp):
    """reads each log lines from a log file"""
    while True:
        line = fp.readline()
        if not line:
            fp.close()
            break
        yield line

def get_file_ptr(path):
    """returns the file pointer to the file by analyzing the type of file"""
    if not get_file_size(path):
        return
    if path.endswith('.zip'):
        opener, mode = zipfile.ZipFile, 'r'
    elif path.endswith('.tar.gz') or path.endswith('.tgz'):
        opener, mode = tarfile.open, 'r:gz'
    elif path.endswith('.tar.bz2') or path.endswith('.tbz'):
        opener, mode = tarfile.open, 'r:bz2'
    else:
        opener, mode = open, 'r'
    
    f = opener(path, mode)
    
    return f

def files():
    options = _parse_args()
    
    options.path = '../../Log_samples'
    print "Bits: ",MAX_BITS
    
    ns=SketchString()
    all_files = get_all_files(options.path)
    for file in all_files:
        print "No of files: "
        fp = get_file_ptr(file)
        if fp:
            iter_file = read_log_file(fp)
            for line in iter_file:
                #print line
                
                ns.getWordText(line)
                ns.displayWordVector()
                ns.display_hashmap_Vector(8)

def Dump_files():
    options = _parse_args()
    
    #options.path = '../../Log_samples/1/'
    

    bloom_vector_nbits=[8,32,64,128,256,512];
    MAX_BITS=bloom_vector_nbits[4]
    print "No of USED BITS: ",MAX_BITS
    print "LOG $ SET_BITS(h1) $ No of tokens"
    all_files = get_all_files(options.path)
    NO_OF_CLUSTERS=0
    for file in all_files:
        #print "No of files: "
        fp = get_file_ptr(file)
        if fp:

            iter_file = read_log_file(fp)
            for line in iter_file:
                #print line
                ns=SketchString()
                ns.getWordText(line)
                #ns.displayWordVector()
                #ns.display_hashmap_Vector(8)
                if line.strip():
                    print line,"$",ns.count_hashmap_Vector(MAX_BITS),"$",ns.count_Word_Vector()
                if not line.strip():
                    NO_OF_CLUSTERS=NO_OF_CLUSTERS+1
    print "NO_OF_CLUSTERS",NO_OF_CLUSTERS

def Comp_log_oneline():
    options = _parse_args()
    
    #python sketching_files.py -p ../../Log_samples/2/
    
    #options.path = '../../Log_samples/2/'
    
    #print options.path
    PER_MATCH=float(options.PER_MATCH)
    print PER_MATCH

    
    bloom_vector_nbits=[8,32,64,128,256,512,1024];
    MAX_BITS=bloom_vector_nbits[6]
    print "No of USED BITS: ",MAX_BITS
    print "INDEX , SET_BITS(h1), SET_BITS(h2), COMMON BITS (AND), HAMMING DISTANCE (XOR), % COMMON(AND/MAX(H1,H2)) , % DIFFERENCE(XOR/MAX(H1,H2)) "
    all_files = get_all_files(options.path)
    for file in all_files:
        #print "No of files: "
        fp = get_file_ptr(file)
        First_line=fp.readline()
        #First_line='8 24 2009-08-14T05:04:11+00:00 Aug 14 05:04:11 192.168.2.150 proftpd[28900]: webhost.mydomain.tld (REMOTEHOST[REMOTEHOST]) - USER web2_brandon (Login failed): Incorrect password'
        #First_line='8 24 2009-08-14T05:04:11+00:00 Aug 14 05:04:11 192.168.2.150 proftpd[28887]: webhost.mydomain.tld (127.0.0.1[127.0.0.10]) - USER web2_brandon: Login successful.'
        First_line='8 24 2009-08-14T05:04:22+00:00 Aug 14 05:04:22 192.168.2.150 ipfw: 4000 Deny Accept UDP 200.13.0.24:48165 192.168.137.3:32 in via x12'
        
        ns=SketchString()
        ns.getWordText(First_line)
        print First_line
        ns.displayWordVector()
        ns.count_hashmap_Vector(MAX_BITS)
        if fp:
            
            iter_file = read_log_file(fp)
            index=0
            for line in iter_file:
                #print line
                h1=ns.count_hashmap_Vector(MAX_BITS)
                ns1=SketchString()
                ns1.getWordText(line)
                h2=ns1.count_hashmap_Vector(MAX_BITS)
                Common_sig,Common_sig_count=ns.Common_bits_signature(ns1)
                Diff_sig,Diff_sig_count=ns.Diff_bits_signature(ns1)
                Imp_sig,Imp_sig_count=ns.Imp_bits_signature(ns1)
                #print Diff_sig_count*1.0/max(h1,h2)
                Per_Diff_sig=Diff_sig_count*1.0/Imp_sig_count
                #Per_Diff_sig=Diff_sig_count*1.0/max(h1,h2)
                #Per_Common_sig=2*Common_sig_count*1.0/(h1+h2)
                Per_Common_sig=Common_sig_count*1.0/Imp_sig_count
                
                #if (Per_Diff_sig<0.5) & (Per_Common_sig>PER_MATCH):
                if (Per_Common_sig>PER_MATCH):
                #if (Diff_sig_count*1.0/max(h1,h2)<0.5) & (Common_sig_count*1.0/max(h1,h2)>0.4):
                    print index,",",h1,",",h2,",",Common_sig_count,",",Diff_sig_count,",",Per_Common_sig,",",Per_Diff_sig
                    print index,"$$$",ns1.displayWordVector()
                    index=index+1

def Comp_log_FILES():
    options = _parse_args()
    
    #python sketching_files.py -p ../../Log_samples/2/
    
    #options.path = '../../Log_samples/2/'
    
    print options.path
    PER_MATCH=float(options.PER_MATCH)
    print PER_MATCH
    bloom_vector_nbits=[8,32,64,128,256,512,1024];
    MAX_BITS=bloom_vector_nbits[5]
    #print "No of USED BITS: ",MAX_BITS
    print "INDEX $LINEINDEX $ SET_BITS(h1)$ SET_BITS(h2)$ COMMON BITS (AND)$ HAMMING DISTANCE (XOR)$ % COMMON(AND/MAX(H1,H2)) $ % DIFFERENCE(XOR/MAX(H1,H2))$ LOGSTRING "
    all_files = get_all_files(options.path)
    for file in all_files:
        #print "No of files: "
        fp = get_file_ptr(file)
        #First_line=fp.readline()
        #First_line='8 24 2009-08-14T05:04:11+00:00 Aug 14 05:04:11 192.168.2.150 proftpd[28900]: webhost.mydomain.tld (REMOTEHOST[REMOTEHOST]) - USER web2_brandon (Login failed): Incorrect password'
        #First_line='8 24 2009-08-14T05:04:11+00:00 Aug 14 05:04:11 192.168.2.150 proftpd[28887]: webhost.mydomain.tld (127.0.0.1[127.0.0.10]) - USER web2_brandon: Login successful.'
        First_line='8 24 2009-08-14T05:04:22+00:00 Aug 14 05:04:22 192.168.2.150 ipfw: 4000 Deny Accept UDP 200.13.0.24:48165 192.168.137.3:32 in via x12'
        
        if fp:
            
            iter_file = read_log_file(fp)
            index=0
            for line in iter_file:
                print line
                ns=SketchString()
                ns.getWordText(line)
                #ns.displayWordVector()
                h1=ns.count_hashmap_Vector(MAX_BITS)
                fp1 = get_file_ptr(file)
                if fp1:
                    iter_file1= read_log_file(fp1)
                    lineindex=0
                    for line1 in iter_file1:
                        ns1=SketchString()
                        ns1.getWordText(line1)
                        h2=ns1.count_hashmap_Vector(MAX_BITS)
                        Common_sig,Common_sig_count=ns.Common_bits_signature(ns1)
                        Diff_sig,Diff_sig_count=ns.Diff_bits_signature(ns1)
                        Imp_sig,Imp_sig_count=ns.Imp_bits_signature(ns1)
                        #print Diff_sig_count*1.0/max(h1$h2)
                        Per_Diff_sig=Diff_sig_count*1.0/Imp_sig_count
                        #Per_Diff_sig=Diff_sig_count*1.0/max(h1,h2)
                        #Per_Common_sig=2*Common_sig_count*1.0/(h1+h2)
                        Per_Common_sig=Common_sig_count*1.0/Imp_sig_count
                        if (Per_Diff_sig<0.5) & (Per_Common_sig>PER_MATCH):
                            #if (Per_Common_sig>PER_MATCH):
                            #if (Diff_sig_count*1.0/max(h1,h2)<0.5) & (Common_sig_count*1.0/max(h1,h2)>0.4):
                            #print index,",",h1,",",h2,",",Common_sig_count,",",Diff_sig_count,",",Per_Common_sig,",",Per_Diff_sig
                            #print index,"$$$",lineindex,"$$$",ns1.displayWordVector()
                            print index,"$",lineindex,"$",h1,"$",h2,"$",Common_sig_count,"$",Diff_sig_count,"$",Per_Common_sig,"$",Per_Diff_sig,"$",line1
                        lineindex=lineindex+1
                index=index+1

def Comp_log():
    options = _parse_args()
    
    #python sketching_files.py -p ../../Log_samples/2/
    
    #options.path = '../../Log_samples/2/'
    
    print options.path
    PER_MATCH=float(options.PER_MATCH)
    print PER_MATCH
    Log_all=[]
    Hashed=[]
    NO_OF_CLUSTERS=0
    all_files = get_all_files(options.path)
    for file in all_files:
        #print "No of files: "
        fp = get_file_ptr(file)
        findex=0
        if fp:
            iter_file = read_log_file(fp)
            for line in iter_file:
                if line.strip():
                    Log_all.append(line)
                    Hashed.append(0)
                    #print line
                    #print Hashed[findex]
                    findex=findex+1

    log_len=len(Log_all)
    bloom_vector_nbits=[8,32,64,128,256,512,1024];
    MAX_BITS=bloom_vector_nbits[5]
                    
    print "No of USED BITS: ",MAX_BITS
    print "No of logs: ",log_len
    print "INDEX $LINEINDEX $ SET_BITS(h1)$ SET_BITS(h2)$ COMMON BITS (AND)$ HAMMING DISTANCE (XOR)$ % COMMON(AND/MAX(H1,H2)) $ % DIFFERENCE(XOR/MAX(H1,H2))$ LOGSTRING "
                    #Hashed[0]=0
    hashed_count=0
    lineindex=0
    count_hash=[]
    one_to_many=[]
    M = [[0 for x in xrange(25)] for x in xrange(log_len)]
    for i in range(log_len):
        ns=SketchString()
        ns.getWordText(Log_all[i])
        h1=ns.count_hashmap_Vector(MAX_BITS)
        count_hash.append(1)
        one_to_many.append(1)        
        #print Log_all[i]
        #if 1:
        if (Hashed[i]==0) & (h1!=0):
            hashed_count=hashed_count+1
            Hashed[i]=hashed_count
            M[i][0]=i
            for j in range(log_len):
                if i!=j:
                    ns1=SketchString()
                    ns1.getWordText(Log_all[j])
                    h2=ns1.count_hashmap_Vector(MAX_BITS)
                    if (h1 | h2) !=0:
                        Common_sig,Common_sig_count=ns.Common_bits_signature(ns1)
                        Diff_sig,Diff_sig_count=ns.Diff_bits_signature(ns1)
                        Imp_sig,Imp_sig_count=ns.Imp_bits_signature(ns1)
                        #   print Diff_sig_count*1.0/max(h1$h2)
                        Per_Diff_sig=Diff_sig_count*1.0/Imp_sig_count
                        Per_Common_sig=Common_sig_count*1.0/Imp_sig_count
                
                        
                    
                        if (Per_Common_sig>PER_MATCH):
                            Hashed[j]=hashed_count
                            count_hash[hashed_count-1]=count_hash[i]+1
                            #M[i][count_hash[i]-1]=j


                            #if (Per_Common_sig>PER_MATCH):
                            #if (Diff_sig_count*1.0/max(h1,h2)<0.5) & (Common_sig*1.0/max(h1,h2)>0.4):
                            #print index,",",h1,",",h2,",",Common_sig_count,",",Diff_sig_count,",",Per_Common_sig,",",Per_Diff_sig
                            #print index,"$$$",lineindex,"$$$",ns1.displayWordVector()
                            #print "I",i,"$J",j,"$",h1,"$",h2,"$",Common_sig_count,"$",Diff_sig_count,"$",Per_Common_sig,"$",Per_Diff_sig,"$",Log_all[j]
                            lineindex=lineindex+1
                            #print i,Hashed[i],j,"--->"count_hash[i]
                                # if (Hashed[i]!=0):
                                    #one_to_many[i]=one_to_many[i]+1
        #else :
                    #print "UnClusters CASE:$$$$$$$",i
            
        print i,"--->",Hashed[i],"--->",count_hash[i]

    for i in range(log_len):
        #if (count_hash[i]==1):
        count_hash[i]=count_hash[Hashed[i]-1]
        print i,"--->",Hashed[i],"--->",count_hash[i]



    print "No of Clusters:",hashed_count,"No of Entry: ",lineindex
#print M



def main():
    
    
    text1 = 'User Manoj logged out.'
    text2 = 'User Basanta logged out.'
    text3 = 'User Manoj Ghimire logged out.'
    text4 = 'User Basanta Joshi logged out.'
    text5 = 'User Basanta logged in.'
    text6 = 'User Manoj Ghimire logged in.'
    
    #text1 = 'This is a foo bar sentence .'
    text2 = 'This sentence is similar to a foo bar sentence .'
    #text1 = '%ASA-6-716038: Group group User user IP ip Authentication: successful, Session Type: WebVPN'
    #text2 = '%ASA-6-716039: Authentication: rejected, group = name user = user, Session Type: WebVPN'
    #text1 = '8 24 2009-08-14T05:04:06+00:00 Aug 14 05:04:06 192.168.2.150 ftpd[91363]: FTP LOGIN FAILED FROM 192.168.1.89, ftpuser'
    #text2 = '8 24 2009-08-14T05:04:16+00:00 Aug 14 05:04:16 192.168.2.150 ftpd[91383]: FTP LOGIN FAILED FROM 192.168.1.91, ftpuser'
    #print "Bits: ",MAX_BITS
    X1='8 24 2009-08-14T05:04:11+00:00 Aug 14 05:04:11 192.168.2.150 proftpd[28900]: webhost.mydomain.tld (REMOTEHOST[REMOTEHOST]) - USER web2_brandon (Login failed): Incorrect password. '
    X2='8 24 2009-08-14T05:04:11+00:00 Aug 14 05:04:11 192.168.2.150 proftpd[28887]: webhost.mydomain.tld (127.0.0.1[127.0.0.10]) - USER web2_brandon: Login successful.'
    ns=SketchString()
    ns.getWordText(X1)
    #ns.displayWordVector()
    
    ns1=SketchString()
    ns1.getWordText(X2)

    print X1
    print X2
    
    print "NO_OF_BITS, SET_BITS(h1), SET_BITS(h2), COMMON BITS (AND), HAMMING DISTANCE (XOR), % COMMON(AND/MAX(H1,H2)) , % DIFFERENCE(XOR/MAX(H1,H2)) "
    bloom_vector_nbits=[8,32,64,128,256,512];
    for i in range(len(bloom_vector_nbits)):
        MAX_BITS=bloom_vector_nbits[i]
        h1=ns.count_hashmap_Vector(MAX_BITS)
        h2=ns1.count_hashmap_Vector(MAX_BITS)
        Common_sig,Common_sig_count=ns.Common_bits_signature(ns1)
        Diff_sig,Diff_sig_count=ns.Diff_bits_signature(ns1)
        Per_Diff_sig=2*Diff_sig_count*1.0/(h1+h2)
                #Per_Diff_sig=Diff_sig_count*1.0/max(h1,h2)
                #Per_Common_sig=2*Common_sig_count*1.0/(h1+h2)
        Per_Common_sig=Common_sig_count*1.0/max(h1,h2)
        print bloom_vector_nbits[i],",",h1,",",h2,",",Common_sig_count,",",Diff_sig_count,",",Common_sig_count*100/max(h1,h2),",",Diff_sig_count*100/max(h1,h2),",",Per_Common_sig*100,",",Per_Diff_sig*100

if __name__=='__main__':

    #print 'Number of arguments:', len(sys.argv), 'arguments.'
    #print 'Argument List:', str(sys.argv)
    #start_time = time.clock()
    Comp_log_oneline()
    Comp_log()
    Dump_files()
    main()
    Comp_log_FILES()
    #print (time.clock() - start_time)/1000, "ms"


