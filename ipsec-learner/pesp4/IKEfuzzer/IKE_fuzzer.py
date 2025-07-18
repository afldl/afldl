import random, ipaddress
from scapy.all import *
from scapy.layers.isakmp import *
from pesp4 import enums, message
from colorama import Fore
import copy

#------------------------------------------------------------
# Chooses an item from a list defined as:
# [(item_1,prob_1), (item_2,prob_2),... ,(item_n,prob_n)]
# where prob_i is the probability of choosing item_i
#------------------------------------------------------------
def weighted_choice(items):
    weight_total = sum((item[1] for item in items))
    n = random.uniform(0, weight_total)
    for item, weight in items:
        if n < weight:
            return item
        n = n - weight
    return item

#------------------------------------------------------------
# The functions below fuzz fields
#------------------------------------------------------------

def rand_ByteEnumField(enumeration=[]):
   if len(enumeration) == 0:
      return random.randint(0, 255)
   else:
      # return random.choice(list(enumeration)).value
      return random.choice(list(enumeration))
      
def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)

def rand_ShortEnumField(enumeration=[]):
   if len(enumeration) == 0:
      return random.randint(0,65535)
   else:
      return random.choice(list(enumeration))
   
def rand_IntEnumField(enumeration=[]):
   if len(enumeration) == 0:
      return random.randint(0,2147483647)
   else:
      return random.choice(list(enumeration))

def rand_StrLenField(data):
   if len(data) <= 1:
      return data
   bit = random.randint(0,2)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + b'\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,100))
   # elif bit == 3:
   #    data = b'\x00'
   return data

def rand_IntField(a=0, b=5000):
   return random.randint(a, b)

def generate_random_bytes(length):
    return bytes(random.randint(0, 255) for _ in range(length))


#------------------------------------------------------------
# The functions to fuzz one specific type IKEv1 payload
#------------------------------------------------------------

def fuzz_Generic(payload):
   if not issubclass(type(payload), message.Payload):
      return
   field = weighted_choice([ ('critical', 0.1), ('data',0.9)])
   if field == 'critical':
      payload.critical = rand_ByteEnumField()
   elif field == 'data':
      payload.data = payload.to_bytes()
      if payload.data:
         payload.data = rand_StrLenField(payload.data)
      
def fuzz_SA_v1(payload):
   if type(payload) != message.PayloadSA_1:
      # print(Fore.RED + 'type(payload) != PayloadSA_1')
      return
   pd = weighted_choice([('SA', 0.2), ('proposal', 0.8)])
   if pd == 'SA':
      # print('fuzzing SA')
      field = weighted_choice([('doi', 0.4), ('situation', 0.4), ('critical', 0.2)])
      if field == 'doi':
         payload.doi = rand_IntEnumField(enums.DOI)
      elif field == 'situation':
         payload.situation = rand_IntField(0, 7)
      elif field == 'critical':
         payload.critical = rand_ByteEnumField()
   elif pd == 'proposal':
      if len(payload.proposals) < 1:
         return
      idx = random.randint(0, len(payload.proposals)-1)
      proposal = payload.proposals[idx]
      fuzz_Proposal_v1(proposal)

def fuzz_Proposal_v1(proposal):
   if type(proposal) != message.Proposal_1:
      # print(Fore.RED + 'type(proposal) != Proposal_1')
      return
   pd = weighted_choice([('proposal', 0.2), ('transform', 0.8)])
   if pd == 'proposal':
      # print('fuzzing proposal')
      field = weighted_choice([('num', 0.2), ('protocol',0.4), ('spi', 0.4)])
      if field == 'num':
         proposal.num = rand_IntField(0, 3)
      elif field == 'protocol':
         proposal.protocol = rand_ByteEnumField(enums.Protocol)
      elif field == 'spi':
         proposal.spi = generate_random_bytes(4)
   elif pd == 'transform':
      if len(proposal.transforms) < 1:
         return
      idx = random.randint(0, len(proposal.transforms)-1)
      transform = proposal.transforms[idx]
      proposal.transforms[idx] = fuzz_Transform_v1(transform, proposal.protocol)

def fuzz_Transform_v1(transform, prot):
   # print('fuzzing transform')
   num = transform.num
   id = transform.id
   values = transform.values
   field = weighted_choice([('num', 0.1), ('id',0.2), ('values', 0.7)])
   if field == 'num':
      num = rand_IntField(0, 3)
   elif field == 'id':
      if prot == enums.Protocol.ESP:
         id = rand_ByteEnumField(enums.EncrId)
      else:
         id = rand_ByteEnumField(enums.Protocol)
   elif field == 'values':
      t = weighted_choice([('remove',0.3), ('change', 0.7)])
      if t == 'remove':
         if len(values) < 1:
            return
         key = random.choice(list(values.keys()))
         values.pop(key)
      elif t == 'change':
         if prot == enums.Protocol.ESP:
            values[random.choice(list(enums.ESPAttr))] = rand_ShortEnumField()
         else:
            values[random.choice(list(enums.TransformAttr))] = rand_ShortEnumField()

   return message.Transform_1(num, id, values)
   
def fuzz_ID_v1(payload):
   if type(payload) != message.PayloadID_1:
      # print(Fore.RED + 'type(payload) != PayloadID_1')
      return
   field = weighted_choice([('id_type', 0.3), ('id_data',0.2), ('prot', 0.2), ('port', 0.2), ('critical',0.1)])
   if field == 'id_type':
      payload.id_type = rand_ByteEnumField(enums.IDType)
   elif field == 'id_data':
      payload.id_data = rand_StrLenField(payload.id_data)
   elif field == 'prot':
      payload.prot = rand_ByteEnumField(enums.IpProto)
   elif field == 'port':
      payload.port = rand_ShortEnumField()
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()
      
def fuzz_Notify_v1(payload):
   if type(payload) != message.PayloadNOTIFY_1:
      # print(Fore.RED + 'type(payload) != PayloadNOTIFY_1')
      return
   field = weighted_choice([('doi', 0.1), ('protocol',0.1), ('notify', 0.5),
                            ('spi',0.1), ('data', 0.1), ('critical',0.1)])
   if field == 'doi':
      payload.doi = random.choice(list(enums.DOI))
   elif field == 'protocol':
      payload.protocol = random.choice(list(enums.Protocol))
   elif field == 'notify':
      payload.notify = random.choice(list(enums.Notify))
   elif field == 'spi':
      payload.spi = rand_StrLenField(payload.spi)
      if len(payload.spi) > 255:
         payload.spi = payload.spi[0:255]
   elif field == 'data':
      payload.data = rand_StrLenField(payload.data)
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()

def fuzz_Delete_v1(payload):
   if type(payload) != message.PayloadDELETE_1:
      # print(Fore.RED + 'type(payload) != PayloadDELETE_1')
      return
   field = weighted_choice([('doi', 0.2), ('protocol',0.2), ('spis', 0.6)])
   if field == 'doi':
      payload.doi = random.choice(list(enums.DOI))
   elif field == 'protocol':
      payload.protocol = random.choice(list(enums.Protocol))
   elif field == 'spis':
      t = weighted_choice([('insert',0.5), ('remove', 0.5)])
      if t == 'insert':
         if random.randint(0, 1) == 0:
            payload.spis.append(generate_random_bytes(4))
         else:
            payload.spis.append(generate_random_bytes(8))
      elif t == 'remove':
         if len(payload.spis) < 1:
            return
         element = random.choice(payload.spis)
         payload.spis.remove(element)

#------------------------------------------------------------
# The functions to fuzz one specific type IKEv2 payload
#------------------------------------------------------------

def fuzz_SA(payload):
   if type(payload) != message.PayloadSA:
      # print(Fore.RED + 'type(payload) != PayloadSA')
      return
   pd = weighted_choice([('SA', 0), ('proposal', 0.9)])
   if pd == 'SA':
      payload.critical = rand_ByteEnumField()
   elif pd == 'proposal':
      if len(payload.proposals) < 1:
         return
      idx = random.randint(0, len(payload.proposals)-1)
      proposal = payload.proposals[idx]
      fuzz_Proposal(proposal)

def fuzz_Proposal(proposal):
   if type(proposal) != message.Proposal:
      # print(Fore.RED + 'type(proposal) != Proposal')
      return
   pd = weighted_choice([('proposal', 0.2), ('transform', 0.8)])
   if pd == 'proposal':
      # print('fuzzing proposal')
      field = weighted_choice([('num', 0), ('protocol',0.4), ('spi', 0)])
      if field == 'num':
         proposal.num = rand_IntField(0, 3)
      elif field == 'protocol':
         proposal.protocol = rand_ByteEnumField(enums.Protocol)
      elif field == 'spi':
         proposal.spi = generate_random_bytes(4)
   elif pd == 'transform':
      if len(proposal.transforms) < 1:
         return
      idx = random.randint(0, len(proposal.transforms)-1)
      transform = proposal.transforms[idx]
      proposal.transforms[idx] = fuzz_Transform(transform)

def fuzz_Transform(transform):
   # print('fuzzing transform')
   type = transform.type
   id = transform.id
   keylen = transform.keylen
   field = weighted_choice([('type', 0.5), ('id',0.5)])
   if field == 'type':
      type = rand_ByteEnumField(enums.Transform)
   elif field == 'id':
      id = rand_ByteEnumField(enums.TransformTable[type])
   return message.Transform(type, id, keylen)       

def fuzz_KE(payload):
   if type(payload) != message.PayloadKE:
      return
   field = weighted_choice([ ('critical', 0), ('dh_group', 0.5), ('ke_data', 0.5)])
   if field == 'dh_group':
      payload.dh_group = random.choice(list(enums.DhId))
   elif field == 'ke_data':
      # payload.ke_data = rand_StrLenField(payload.ke_data)
      payload.ke_data = b''
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()

def fuzz_ID(payload):
   if type(payload) != message.PayloadIDi and type(payload) != message.PayloadIDr:
      # print(Fore.RED + 'type(payload) != PayloadID_1')
      return
   field = weighted_choice([('id_type', 0.3), ('id_data',0.2), ('prot', 0.2), ('port', 0.2), ('critical',0)])
   if field == 'id_type':
      payload.id_type = random.choice(list(enums.IDType))
   elif field == 'id_data':
      payload.id_data = rand_StrLenField(payload.id_data)
   elif field == 'prot':
      payload.prot = random.choice(list(enums.IpProto))
   elif field == 'port':
      payload.port = rand_ShortEnumField()
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()
      
def fuzz_AUTH(payload):
   if type(payload) != message.PayloadAUTH:
      return
   field = weighted_choice([('method', 0.7), ('auth_data',0.3), ('critical',0)])
   if field == 'method':
      correct_method = payload.method
      while payload.method == correct_method:
         payload.method = random.choice(list(enums.AuthMethod))
   elif field == 'auth_data':
      payload.auth_data = rand_StrLenField(payload.auth_data)
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()

def fuzz_Notify(payload):
   if type(payload) != message.PayloadNOTIFY:
      return
   field = weighted_choice([('protocol',0.5), ('notify', 0.2),
                            ('spi',0.1), ('data', 0.1), ('critical',0)])
   if field == 'protocol':
      payload.protocol = random.choice(list(enums.Protocol))
   elif field == 'notify':
      payload.notify = random.choice(list(enums.Notify))
   elif field == 'spi':
      payload.spi = rand_StrLenField(payload.spi)
      if len(payload.spi) > 8:
         payload.spi = payload.spi[0:8]
   elif field == 'data':
      payload.data = rand_StrLenField(payload.data)
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()

def fuzz_Delete(payload):
   return
   if type(payload) != message.PayloadDELETE:
      return
   field = weighted_choice([('protocol',0.4), ('spis', 0.6), ('critical',0)])
   if field == 'protocol':
      payload.protocol = random.choice(list(enums.Protocol))
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()
   elif field == 'spis':
      t = weighted_choice([('insert',0.5), ('remove', 0.5)])
      if t == 'insert':
         if random.randint(0, 1) == 0:
            payload.spis.append(generate_random_bytes(4))
         else:
            payload.spis.append(generate_random_bytes(8))
      elif t == 'remove':
         if len(payload.spis) < 1:
            return
         element = random.choice(payload.spis)
         payload.spis.remove(element)

def fuzz_TS(payload):
   if type(payload) != message.PayloadTSi and type(payload) != message.PayloadTSr:
      return
   field = weighted_choice([('critical', 0), ('traffic_selectors', 0.8)])
   if field == 'critical':
      payload.critical = rand_ByteEnumField()
   elif field == 'traffic_selectors':
      if len(payload.traffic_selectors) < 1:
         return
      idx = random.randint(0, len(payload.traffic_selectors)-1)
      ts = payload.traffic_selectors[idx]
      fuzz_ts(ts)

def fuzz_ts(ts):
   # print('fuzzing traffic_selector')
   if type(ts) != message.TrafficSelector:
      return
   field = weighted_choice([('ts_type',0.1), ('ip_proto', 0.1), ('start_port',0.1),
                           ('end_port', 0.1), ('start_addr',0), ('end_addr', 0)])
   if field == 'ts_type':
      ts.ts_type = random.choice(list(enums.TSType))
   elif field == 'ip_proto':
      ts.ip_proto = random.choice(list(enums.IpProto))
   elif field == 'start_port':
      ts.start_port = rand_ShortEnumField()
   elif field == 'end_port':
      ts.end_port = rand_ShortEnumField()
   # elif field == 'start_addr':
   #    ts.start_addr = ipaddress.ip_address('192.168.0.1')
   # elif field == 'end_addr':
   #    ts.end_addr = ipaddress.ip_address('192.168.0.1')

def fuzz_cert(payload):
   if type(payload) != message.PayloadCERT or type(payload) != message.PayloadCERTREQ:
      return
   field = weighted_choice([('encoding', 0.7), ('data',0.2), ('critical',0)])
   if field == 'encoding':
      payload.encoding = random.choice(list(enums.CertCode))
   elif field == 'data':
      payload.data = rand_StrLenField(payload.data)
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()
      
def fuzz_eap(payload):
   if type(payload) != message.PayloadEAP:
      return
   field = weighted_choice([('code', 0.7), ('data',0.2), ('critical',0)])
   if field == 'code':
      payload.code = random.choice(list(enums.EAPCode))
   elif field == 'data':
      payload.data = rand_StrLenField(payload.data)
   elif field == 'critical':
      payload.critical = rand_ByteEnumField()

def fuzz_NONCE(payload):
   return

#------------------------------------------------------------
# Map <payload id> <--> <function that fuzzes one ayload>
#------------------------------------------------------------
fuzz_func = {
   # IKEv1
   enums.Payload.SA_1: fuzz_SA_v1,
   enums.Payload.KE_1: fuzz_Generic,
   enums.Payload.ID_1: fuzz_ID_v1,
   enums.Payload.CERT_1: fuzz_Generic,
   enums.Payload.CERTREQ_1: fuzz_Generic,
   enums.Payload.HASH_1: fuzz_Generic,
   enums.Payload.SIG_1: fuzz_Generic,
   enums.Payload.NONCE_1: fuzz_Generic,
   enums.Payload.NOTIFY_1: fuzz_Notify_v1,
   enums.Payload.DELETE_1: fuzz_Delete_v1,
   enums.Payload.VENDOR_1: fuzz_Generic,
   enums.Payload.CP_1: fuzz_Generic,
   enums.Payload.NATD_1: fuzz_Generic,
   
   # IKEv2
   enums.Payload.SA: fuzz_SA,
   enums.Payload.KE: fuzz_KE,
   enums.Payload.IDi: fuzz_ID,
   enums.Payload.IDr: fuzz_ID,
   enums.Payload.CERT: fuzz_cert,
   enums.Payload.CERTREQ: fuzz_cert,
   enums.Payload.AUTH: fuzz_AUTH,
   enums.Payload.NONCE: fuzz_NONCE,
   enums.Payload.NOTIFY: fuzz_Notify,
   enums.Payload.DELETE: fuzz_Delete,
   enums.Payload.VENDOR: fuzz_Generic,
   enums.Payload.TSi: fuzz_TS,
   enums.Payload.TSr: fuzz_TS,
   enums.Payload.EAP: fuzz_eap
}

#------------------------------------------------------------
# This function randomly generate one payload
#------------------------------------------------------------
def randomly_generate_one_payload_v1():
   payload_class = [enums.Payload.NOTIFY_1, enums.Payload.SIG_1, 
                    enums.Payload.CP_1, enums.Payload.NATD_1]
   payload_type = random.choice(payload_class)
   payload = None
   if payload_type == enums.Payload.NOTIFY_1:
      payload = message.PayloadNOTIFY_1(doi=random.choice(list(enums.DOI)), 
               protocol=random.choice(list(enums.Protocol)), 
               notify=random.choice(list(enums.Notify)),
               spi=generate_random_bytes(4), 
               data=generate_random_bytes(random.randint(0, 255)))
   elif payload_type == enums.Payload.SIG_1:
      payload = message.PayloadSignature_1(
               signature_data=generate_random_bytes(random.randint(0, 255)))
   elif payload_type == enums.Payload.CP_1:
      data = b'\x80\x00' + generate_random_bytes(2)
      payload = message.PayloadCP_1(type=random.choice(list(enums.CFGType)),
               attrs=message.attr_parse(io.BytesIO(data), 4, enums.CPAttrType))
   elif payload_type == enums.Payload.NATD_1:
      payload = message.PayloadNATD_1(data=generate_random_bytes(random.randint(0, 255)))
   return payload   

def randomly_generate_one_payload_v2():
   payload_class = [enums.Payload.NOTIFY, enums.Payload.CP, enums.Payload.EAP]
   payload_type = random.choice(payload_class)
   payload = None
   if payload_type == enums.Payload.NOTIFY:
      payload = message.PayloadNOTIFY(enums.Protocol.IKE, random.choice(list(enums.Notify)),
                                      spi=b'', data=b'')
   elif payload_type == enums.Payload.CP:
      data = b'\x80\x00' + generate_random_bytes(2)
      payload = message.PayloadCP(type=random.choice(list(enums.CFGType)),
               attrs=message.attr_parse(io.BytesIO(data), 4, enums.CPAttrType))
   elif payload_type == enums.Payload.EAP:
      payload = message.PayloadEAP(code=random.choice(list(enums.EAPCode)), 
               data=generate_random_bytes(random.randint(0, 255)))
   return payload   

#------------------------------------------------------------
# Help function 
#------------------------------------------------------------
def combine_abstract_symbol(ex_type, payloads):
   if '' in payloads:
      payloads.remove('')
   symbol = f'{ex_type}_'
   for pd in payloads:
      symbol += f'{pd}-'
   return symbol.strip('-')

supported_IKEv2_payload = ['SA', 'KE', 'NONCE', 'IDi', 'AUTH', 'TSi', 'TSr', 'DelChild', 'DelOldChild', 'DelIKE', 'RekeySA', 'TransMode', 'CERT', 'CERTREQ']
def fuzz_one_abstract_symbol(abs: str, prob_list = [('repeat', 0.1), ('remove', 0.1), ('insert', 0.1)]):
   fuzzed = False
   t = abs.split('_')[0]
   pds = abs.split('_')[1].split('-')
   while not fuzzed:
      fuzz_type = weighted_choice(prob_list)
      if fuzz_type == 'repeat':
         if len(pds) < 1 or len(pds) > 10:
            continue
         index1 = random.randint(0, len(pds)-1)
         index2 = random.randint(0, len(pds))
         pd = pds[index1]
         pds.insert(index2, pd)
         fuzzed = True
      elif fuzz_type == 'remove':
         if len(pds) < 1:
            continue
         index = random.randint(0, len(pds)-1)
         pds.remove(pds[index])
         fuzzed = True
      elif fuzz_type == 'insert':
         if len(pds) > 10:
            continue
         index = random.randint(0, len(pds))
         pds.insert(index, random.choice(supported_IKEv2_payload))
         fuzzed = True
      abs = combine_abstract_symbol(t, pds)
   return abs
   
   
class IKE_fuzzer:
   def __init__(self, version='v1', prob_list = [('header', 0), ('payload', 0), ('field', 0.8)]):
      self.prob_list = prob_list
      self.version = version
   
   def fuzz_one_message(self, msg, abs=None):
      if type(msg) != message.Message:
         return abs
      if len(msg.payloads) < 1:
         return abs
      stack = random.randint(1, 1)
      for _ in range(0, stack):
         fuzz_level = weighted_choice([('header', 0.1), ('payload', 0)]) if len(msg.payloads) < 1 else weighted_choice(self.prob_list)
         if fuzz_level == 'header':
            self.fuzz_header(msg)
            if abs is not None:
               t = abs.split('_')[0] + '*'
               pds = abs.split('_')[1].split('-')
               abs = combine_abstract_symbol(t, pds)
         elif fuzz_level == 'payload':
            if abs is not None:
               abs = self.fuzz_payload_level(msg.payloads, abs)
            else:
               self.fuzz_payload_level(msg.payloads)
         elif fuzz_level == 'field':
            idx = random.randint(0, len(msg.payloads)-1)
            payload = msg.payloads[idx]
            self.fuzz_field_level(payload)
            if abs is not None:
               t = abs.split('_')[0]
               pds = abs.split('_')[1].split('-')
               # print(pds)
               pds[idx] += '*' if '*' not in pds[idx] else ''
               abs = combine_abstract_symbol(t, pds)
      return abs
   
   def fuzz_one_message_in_specific_location(self, msg, abs):
      if type(msg) != message.Message or len(msg.payloads) < 1:
         return
      hdr = abs.split('_')[0]
      pds = abs.split('_')[1].split('-')
      if '*' in hdr:
         self.fuzz_header(msg)
      else:
         fuzzed_pd_index = None
         for i in range(len(pds)):
            if '*' in pds[i]:
               fuzzed_pd_index = i
         if fuzzed_pd_index is not None:
            payload = msg.payloads[fuzzed_pd_index]
            self.fuzz_field_level(payload)
   
   def fuzz_header(self, message):
      fuzz_field = weighted_choice( [('version', 0), ('exchange', 0), ('flag', 0), ('message_id', 0.1)] )
      if fuzz_field == 'version':
         message.version = rand_ByteEnumField()
      elif fuzz_field == 'exchange':
         message.exchange = random.choice(list(enums.Exchange))
      elif fuzz_field == 'flag':
         message.flag = random.choice(list(enums.MsgFlag))
      elif fuzz_field == 'message_id':
         message.message_id = rand_IntEnumField()
   
   def fuzz_payload_level(self, payloads, abs=None):
      fuzzed = False
      while not fuzzed:
         fuzz_type = weighted_choice( [('repeat', 0.1), ('remove', 0.1), ('insert', 0.1)] )
         if abs is not None:
            t = abs.split('_')[0]
            pds = abs.split('_')[1].split('-')
         if fuzz_type == 'repeat':
            if len(payloads) < 1 or len(payloads) > 10:
               continue
            index1 = random.randint(0, len(payloads)-1)
            payload = copy.deepcopy(payloads[index1])
            index2 = random.randint(0, len(payloads))
            payloads.insert(index2, payload)
            pd = pds[index1]
            pds.insert(index2, pd)
            fuzzed = True
         elif fuzz_type == 'remove':
            if len(payloads) < 1:
               continue
            index = random.randint(0, len(payloads)-1)
            payload = payloads[index]
            payloads.remove(payload)
            pds.remove(pds[index])
            fuzzed = True
         elif fuzz_type == 'insert':
            if len(payloads) > 10:
               continue
            if self.version == 'v1':
               payload = randomly_generate_one_payload_v1()
            else:
               payload = randomly_generate_one_payload_v2()
            if payload:
               index = random.randint(0, len(payloads))
               payloads.insert(index, payload)
               ptype = str(payload.type).replace('Payload.', '')
               pds.insert(index, ptype)
               fuzzed = True
         if abs is not None:
            abs = combine_abstract_symbol(t, pds)
      return abs
            
   def fuzz_field_level(self, payload):
      payload_type = payload.type
      fuzz_func.get(payload_type, fuzz_Generic)(payload)

            
    

