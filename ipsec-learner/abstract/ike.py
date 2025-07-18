import argparse
from scapy.all import *
from collections import Counter

from pesp4 import enums
from pesp4.message import *
from aalpy.learning_algs import run_RPNI

def select_isakmp(packets):
    ps=[]
    for i in packets:
        try:
            if len(i['ISAKMP'])> 0:
                ps.append(i)
        except:
            pass
    return ps

def gen_flow(p):
    a=[]
    i=1
    spi_1=p[0]['ISAKMP'].init_cookie
    aa=[]
    aa.append(p[0])
    while(i<len(p)):
        spi_2=p[i]['ISAKMP'].init_cookie
        if spi_2==spi_1:
            aa.append(p[i])
            i=i+1
        else:
            a.append(aa)
            aa=[]
            spi_1=spi_2
            aa.append(p[i])
            i=i+1
    if(spi_1==spi_2):
        a.append(aa)
    return a

def process_letter(p):
    data = bytes(p['ISAKMP'])
    stream = io.BytesIO(data)
    msg = Message.parse(stream)
    abstract = ''  
    for key, value in enums.exchangeMap.items():
        if value == msg.exchange:
            abstract += key + '_'
    try:
        msg.parse_payloads(stream)
    except:
        abstract += 'cipher'
        return abstract
        
    
    for pd in msg.payloads:
        abbr = (str(pd.type).split('Payload.')[1] + '-')
        if pd.type == enums.Payload.NOTIFY_1:
            abbr = str(pd.notify).split('Notify.')[1] + '-'
        elif pd.type == enums.Payload.NOTIFY:
            abbr = str(pd.notify).split('Notify.')[1] + '-'
        abstract += abbr        
    abstract = f"{abstract.strip('-')}"
    return abstract

def gen_query(k):
    a=[]
    for i in k:
        aa=[]
        src = i[0]['IP'].src
        for j in i:
            sr = 'send' if j['IP'].src== src else 'recv'
            al = process_letter(j)
            aa.append(f'{sr}({al})')
        a.append(aa)
    return a

def process_pcap(filename:str):
    print(f"读取{filename}文件")
    packets = rdpcap(filename)
    time.sleep(1)
    
    print("分析并选择isakmp报文")
    ppp=select_isakmp(packets)
    time.sleep(1)

    print("生成流数据")
    kk=gen_flow(ppp)
    time.sleep(1)

    print("形式化转化")
    bb=gen_query(kk)
    time.sleep(1)
    return bb

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

def extract_automaton(filename:str):
    bb = process_pcap(filename)
    ll=trans_query(bb)
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
    print("保存状态机")
    rpni_model.visualize(file_type='dot')
    
if len(sys.argv) < 3:
    sys.exit("Too few arguments provided.\nUsage: python3 ike.py 'func[1.only abstraction 2.extract automaton]' 'pcap file'")
func = sys.argv[1]
file = sys.argv[2]
if func == '1':
    bb = process_pcap(file)
    with open(f'abstract_{file.split(".pcapng")[0]}.txt', 'w') as f:
        for i in range(len(bb)):
            f.write(f'数据流{i}: {bb[i]}\n')
    print(f'形式化表示已保存至abstract_{file.split(".pcapng")[0]}.txt')
else:
    extract_automaton(file)
