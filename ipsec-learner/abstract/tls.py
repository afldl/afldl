from scapy.all import *
from aalpy.learning_algs import run_RPNI
from collections import Counter

load_layer("tls")

def select_TLS(packets):
    ps=[]
    for i in packets:
        try:
            if len(i['Raw'])> 0:
                if i.sport==4433:
                    i.sport=443
                    ps.append(i)
                elif i.dport==4433:
                    i.dport=443
                    ps.append(i)
        except:
            pass
    return ps

def choose_port(p):
    if p.sport==443:
        return p.dport
    else:
        return p.sport

def gen_flow(p):
    a=[]
    i=1
    # print (p)
    p1=choose_port(p[0])
    # print(p1)
    aa=[]
    aa.append(p[0])
    while(i<len(p)):
        # print(p[i]['TLS'])
        # print(i)
        p2=choose_port(p[i])
        # print(p2)
        if p1==p2:
            aa.append(p[i])
            i=i+1
        else:
            a.append(aa)
            aa=[]
            p1=p2
            aa.append(p[i])
            i=i+1
    if(p1==p2):
        a.append(aa)
    return a

def process_letter(p):
    a=[]
    aa=[]
    for i in p:
        # print(len(i))
        for j in i:
            # print(j.sport,j)
            # print(j.sport)
            if j.sport==443:
                try:
                    msg=''
                    if j['TLS']['TLS Handshake - Server Hello'].msgtype == 2:
                        # print("asfdewqf")
                        msg='SH+CERT'
                        # aa.append("rsv(SH")
                        # aa.append("rsv()")
                    if j['TLS']['TLS Handshake - Server Key Exchange'].msgtype == 12:
                        # aa.append("rsv(SKE)")
                        msg=msg+'+SKE'
                    if j['TLS']['TLS Handshake - Server Hello Done'].msgtype == 14:
                        # aa.append("rsv(SHD)") 
                        msg=msg+'+SHD'
                    # a.append()
                    if len(msg)>0:
                        aa.append('recv('+msg+')')
                except:
                    pass
                try:
                    if j['TLS'].type == 21:
                        aa.append("recv(Alert)")
                except:
                    pass
                try:
                    if j['TLS'].type == 20:
                        aa.append("recv(CCS)")
                except:
                    pass
                try:
                    if j['TLS'].type == 23:
                        aa.append("recv(AD)")
                except:
                    pass
            # j.show()
            
                # if j['TLS']['Raw'].load[0:1]=='\x0f':
                
                    # print("hh")
                    # j.show()
                    # print(j['TLS']['TLS Handshake - Server Hello'].msgtype)
                    # if j['TLS']['TLS Handshake - Client Hello'].msgtype == 1:
                    #     aa.append("rsv(CH)")
                                       
                    
                    
                    
            if j.dport==443:
                try:
                    if j['TLS']['TLS Handshake - Client Hello'].msgtype == 1:
                        aa.append("send(CH)")
                except:
                    pass
                try:
                    if j['TLS']['Raw'].load[0:1]==b'\x0f':
                        aa.append("send(CV)")
                except:
                    pass
                try:
                    if j['TLS']['Raw'].load[0:1]==b'\x14':
                        aa.append("send(FIN)")
                except:
                    pass
                try:
                    if j['TLS'].type == 21:
                        aa.append("send(Alert)")
                except:
                    pass
                try:
                    if j['TLS'].type == 20:
                        aa.append("send(CCS)")
                except:
                    pass
                try:
                    if j['TLS'].type == 23:
                        aa.append("send(AD)")
                except:
                    pass
                try:
                    if j['TLS'].type == 22 and j['TLS']['Raw'].load[0:1]>b'\x20':
                        aa.append("send(EHM)")
                except:
                    pass
                    # print("hh")

        # print(aa)
        a.append(aa)
        aa=[]
    return a

def process_pcap(file):
    print(f"读取{file}文件")
    packets = rdpcap(file)
    
    print("分析并选择tls报文")
    ps=select_TLS(packets)
    
    wrpcap('a.pcapng', ps)
    packets = rdpcap('a.pcapng')
    
    print("生成流数据")
    bb=gen_flow(packets)
    
    print("形式化转化")
    cc=process_letter(bb)
    return cc

def process_query(a):
    b=[]
    for i in range(len(a)):
        if a[i][0:4]=='send':
            if i<len(a)-1 and a[i+1][0:4]=='recv':
                b.append(a[i][5:-1]+'/'+a[i+1][5:-1])
        if a[i][0:4]=='send':
            if i<len(a)-1 and a[i+1][0:4]=='send':
                b.append(a[i][5:-1]+'/'+ 'no')
        if i==len(a) and a[i][0:4]=='send':
            b.append(a[i][5:-1] + '/' + 'no')

    return b

def trans_query(b):
    a=[]
    for i in b:
        a.append(process_query(i))
    return a

def process_nondeterministic(data, kk):
    t=data
    k=[]
    remove_query=[]
    for i in range (len(data)-1):
        for j in range(i+1,len(data)):
            if data[i][0]==data[j][0]:
                if kk[data[i]]<kk[data[j]]:
                    remove_query.append(data[i])
                else:
                    remove_query.append(data[j])
    for s in list(set(remove_query)):
        t.remove(s)
    return t

def extract_automaton(file):
    cc = process_pcap(file)
    ll=trans_query(cc)
    print("将数据流转变为查询query")
    time.sleep(2)
    s=[]
    for k in ll:
        c1 = []
        for i in k:
            c1.append(i[0:i.find('/')])
            c2 = i[i.find('/') + 1:]
            v = [tuple(c1), c2]
            s.append(tuple(v))
    kk=Counter(s)
    data=list(set(s))
    data=process_nondeterministic(data, kk)
    print("生成状态机")
    time.sleep(2)
    rpni_model = run_RPNI(data, automaton_type='mealy', print_info=False)
    print("状态机展示")
    time.sleep(1)
    rpni_model.visualize(file_type='dot')


if len(sys.argv) < 3:
    sys.exit("Too few arguments provided.\nUsage: python3 tls.py 'func[1.only abstraction 2.extract automaton]' 'pcap file'")
func = sys.argv[1]
file = sys.argv[2]
if func == '1':
    res = process_pcap(file)
    with open(f'abstract_{file.split(".pcapng")[0]}.txt', 'w') as f:
        for i in range(len(res)):
            f.write(f'数据流{i}: {res[i]}\n')
    print(f'形式化表示已保存至abstract_{file.split(".pcapng")[0]}.txt')
else:
    extract_automaton(file)



