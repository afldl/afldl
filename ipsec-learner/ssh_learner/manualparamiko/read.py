import json


with open("../../../username&password.json",'r') as load_f:
    data = json.load(load_f)
    print(data['username'])
    print(data['password'])