import os
import sys
import time
import libnum
import json
import socket
import hmac
import hashlib
from utilise.cpabe import *
from utilise.myRSA import HandleRSA
import utilise.myAES as AES
# import AM
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as extractor
##########################################################################################
USER_ID = sys.argv[1]
PK_PATH = "User"+str(USER_ID)+"/User"+str(USER_ID)+".pub"
SK_PATH = "User"+str(USER_ID)+"/User"+str(USER_ID)+".key"
INFOLIST_PATH = "User"+str(USER_ID)+"/User"+str(USER_ID)+".json"
USER_INFO = dict()
MAXBUFFSIZE = 51200
BUFFSIZE = 40960
BUFFSIZE_SENT = 20480
OWNER_ADDRESS = ("127.0.0.1", 12345)
AM_ADDRESS = ("127.0.0.1", 22347)
##########################################################################################
groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)

# 初始化用户信息表
def initList(path):
    with open(path,"w") as f:
        json.dump(USER_INFO,f)
    f.close()

# 更新USER_INFO
def updateList(path,tardata,userdata):
    with open(path,"r+") as f:
        userList = json.load(f)
        userList["value"][tardata] = userdata
        f.seek(0)
        f.truncate()
        json.dump(userList,f)
    f.close()

# 获取目标用户的USER_INFO
def getList(path):
    with open(path,"r") as f:
        userList = json.load(fp=f)
    return userList

# 初始化
def init_du(ownid):
    global USER_INFO, USER_ID
    USER_ID = ownid
    USER_INFO = {"key":ownid,"value":{"identify":"DU","attrStateList":{},"roleStateList":{},\
    "askUserRoleList":[],"currentRoleList":[],"currentAttrList":[],"askAccessList":[],\
    "session":False,"askForKey":{},"pk":None}}
    rsa_pk = HandleRSA().create_rsa_key(PK_PATH)
    with open(PK_PATH,"r") as f:
        rsa_pk = f.read()
    USER_INFO["value"]["pk"] = rsa_pk
    initList(INFOLIST_PATH)

# 请求EncryptSK
def getEnSK(ownerid,userid):
    ownerfile_path = "User"+str(USER_ID)+"/User"+str(ownerid)+".json"
    userfile_path = "User"+str(USER_ID)+"/User"+str(userid)+".json"
    if(not os.path.exists(ownerfile_path)):
        print("Invalid User!")
        return False
    else:
        userlist = getList(userfile_path)["value"]["askForKey"]
        ownerlist = getList(ownerfile_path)["value"]
        if(userlist[str(ownerid)] == "ACCEPT"):
            return ownerlist["sk"][str(userid)]
        else:
            print("Timed out or no permission!")
            return False

# 请求CP-ABE公钥PK
def getPK(ownerid):
    file_path = "User"+str(USER_ID)+"/User"+str(ownerid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        ownerlist = getList(file_path)
        return bytesToObject(ownerlist["value"]["PK"].encode(),groupObj)

# CP-ABE密钥ensk解密
def decryptSK(encrypt_sk):
    time_stamp = time.time()
    mrsa = HandleRSA()
    decrypt_sk = []
    sk = open(SK_PATH).read()
    for i in range(0,len(encrypt_sk[0])):
        decrypt_sk.append(mrsa.decrypt(sk, encrypt_sk[0][i]))
    deres = "".join(decrypt_sk)
    desk = bytesToObject(deres.encode(), groupObj)
    return desk

# 获取密钥密文CTK
def getCTK(ownerid,datanote):
    ownerfile_path = "User"+str(USER_ID)+"/User"+str(ownerid)+".json"
    ownerList = getList(ownerfile_path)["value"]["duList"]
    owner = getList(ownerfile_path)["value"]
    userList = getList(INFOLIST_PATH)["value"]["askAccessList"]
    now = time.time()
    for i in range(len(userList)):
        if(userList[i]["doId"] == ownerid and userList[i]["currentState"] == "AGREE"):
            for j in range(len(ownerList)):
                time_stamp = time.mktime(time.strptime(ownerList[j]["time"],"%Y-%m-%d"))
                if(now > time_stamp):
                    ownerList[j]["accessState"] = "REVOKE"
                    userList[i]["currentState"] = "REVOKE"
                    updateList(ownerfile_path,"duList",ownerList)
                    updateList(INFOLIST_PATH,"askAccessList",userList)
                if(ownerList[j]["accessState"] == "ACCEPT"):
                    for k in owner["dataList"]:
                        if(k["dataNote"] == datanote):
                            ctk = bytesToObject(k["ct"].encode(),groupObj)
                            hmac = k["hmac"]
                            return ctk, hmac
                        else:
                            print("[!] DataNote Wrong!")
                            return False
                else:
                    print("[!] Timed out or no permission!")
                    return False
        else:
            print("[!] UesrID Wrong or no permission!")
            return False

# 请求角色
def reqRole(userid,reqrolelist):
    userList = getList(INFOLIST_PATH)
    if(userid != userList["key"]):
        print("USERID Wrong!")
        exit(-1)
    roleList = userList["value"]["roleStateList"]
    for i in reqrolelist:
        if(i not in roleList.keys()):
            roleList[i] = "REQUEST"
        else:
            continue
    updateList(INFOLIST_PATH,"roleStateList",roleList)

# 请求属性
def reqAttr(userid,reqattrlist):
    userList = getList(INFOLIST_PATH)
    if(userid != userList["key"]):
        print("USERID Wrong!")
        exit(-1)
    attrList = userList["value"]["attrStateList"]
    for i in reqattrlist:
        if(i not in attrList.keys()):
            attrList[i] = "REQUEST"
        else:
            continue
    updateList(INFOLIST_PATH,"attrStateList",attrList)

# 请求激活用户角色
def reqActiveRole(userid,askRoleList):
    userList = getList(INFOLIST_PATH)
    if(userid != userList["key"]):
        print("USERID Wrong!")
        exit(-1)
    roleList = userList["value"]["askUserRoleList"]
    for i in range(len(askRoleList)):
        if(askRoleList[i] not in roleList):
            roleList.append(askRoleList[i])
        else:
            continue
    updateList(INFOLIST_PATH,"askUserRoleList",roleList)
    updateList(INFOLIST_PATH,"session",True)

# 请求密钥
def reqSK(userid,ownerid):
    userList = getList(INFOLIST_PATH)
    if(userid != userList["key"]):
        print("USERID Wrong!")
        exit(-1)
    keystate = userList["value"]["askForKey"]
    keystate[ownerid] = "ASK"
    updateList(INFOLIST_PATH,"askForKey",keystate)

# 解密CTK
def decryptCTK(ownpk,ownsk,ctk):
    rec_msg = cpabe.decrypt(ownpk, ownsk, ctk)
    if(rec_msg):
        print("[*] SK Successful Decryption!")
    else:
        print("[!] SK FAILED Decryption: message is incorrect!")
    key = extractor(rec_msg)
    return key

# 验证摘要        
def verify(key,msg,_hmac):
    mac = hmac.new(key,msg,hashlib.md5)
    signature = mac.hexdigest()
    if(signature == _hmac):
        return True
    else:
        return False

# 请求数据
def reqData(ownerid,askdatalist):
    flag = 0
    userList = getList(INFOLIST_PATH)["value"]
    reqdataList = userList["askAccessList"]
    temp = dict()
    temp["doId"] = ownerid
    temp["askDataList"] = askdatalist
    temp["currentState"] = "REQUEST"
    for i in range(len(reqdataList)):
        if(reqdataList[i]["doId"] == temp["doId"] and reqdataList[i]["askDataList"] == temp["askDataList"]):
            flag += 1
    if(flag == 0):
        reqdataList.append(temp)
    updateList(INFOLIST_PATH,"askAccessList",reqdataList)
# test
# def getCTK_test():
#     with open(CT_PATH) as f:
#         ctk = f.read()
#     f.close()
#     ctk = bytesToObject(ctk.encode(),groupObj)
#     return ctk

# 数据解密并验证
def DataDecrypt(ct,key,_hmac):
    pt = AES.decrypt(ct,key)
    if(verify(key,pt,_hmac)):
        print("[*] Data Decrypted!")
        return pt.decode('utf-8')
    else:
        print("[!] Verify Failed!")
        return False

def doIint_REQ(userid,reqid):
    init_du(userid)                                       # 初始化DU
    reqRole(userid,["R1"])                                # 请求角色
    reqAttr(userid,["A1","A3"])                           # 请求属性
    reqActiveRole(userid,["R1"])                          # 请求激活角色
    reqSK(userid,reqid)                                   # 请求CP-ABE密钥
    reqData(reqid,["Data1"])                              # 请求数据访问权限

def doAccess(reqid):
    ensk = getEnSK(reqid,USER_ID)                         # 获取加密后的CP-ABE密钥EncryptSK
    ownpk = getPK(reqid)                                  # 获取CP-ABE公钥PK
    ownsk = decryptSK(ensk)                               # 解密获得CP-ABE密钥SK
    ctk ,sig = getCTK(reqid,"Data1")                      # 获取CP-ABE密文CT
    key = decryptCTK(ownpk,ownsk,ctk)                     # 解密CP-ABE密文,得到ABE密钥key
    pt = DataDecrypt("Data1",key,sig)
    print(pt)     


def revjson(ownerid):
    data = json.loads(clientServer.recv(BUFFSIZE).decode())
    path = "User"+str(USER_ID)+"/User"+str(ownerid)+".json"
    with open(path,"w") as f:
        json.dump(data,f)
    f.close()

def sendjson(path):
    userList = getList(path)
    clientServer.send(json.dumps(userList).encode())

def duSocketTest():
    global clientServer
    clientServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        print("\t1. 角色属性申请\n\t2. 权限申请和数据访问\n\t3. 退出")
        op = input("[+] ")
        if(op == "1"):
            clientServer.connect(AM_ADDRESS)
            cmdinfo = clientServer.recv(BUFFSIZE).decode()
            while True:
                command = input(cmdinfo + "\n[+] ")
                while not command:
                    command = input("[+] ")
                clientServer.send(command.encode())
                if(command == "1"):
                    init_du(USER_ID)
                    clientServer.send(str(USER_ID).encode())
                if(command == "2"):
                    reqRole(USER_ID,["R1"])
                    sendjson(INFOLIST_PATH)
                    revjson(USER_ID)
                    print("ok!")
                if(command == "3"):
                    reqAttr(USER_ID,["A1","A3"])
                    sendjson(INFOLIST_PATH)
                    revjson(USER_ID)
                    print("ok!")
                if(command == "4"):
                    reqActiveRole(USER_ID,["R1"])
                    sendjson(INFOLIST_PATH)
                    revjson(USER_ID)
                    print("ok!")
                if(command == "5"):
                    clientServer.close()
                    break
        elif(op == "2"):    
            clientServer.connect(OWNER_ADDRESS)
            # print(clientServer)
            clientServer.send(str(USER_ID).encode())
            sendjson(INFOLIST_PATH)
            cmdinfo = clientServer.recv(BUFFSIZE).decode()
            while True:
                command = input(cmdinfo + "\n[+] ")
                while not command:
                    command = input("[+] ")
                clientServer.send(command.encode())
                if(command == "1"):
                    revjson(10)
                    reqSK(USER_ID,10)
                    sendjson(INFOLIST_PATH)
                    revjson(USER_ID)
                
                if(command == "2"):
                    revjson(10)
                    reqData(10,["Data1"])
                    sendjson(INFOLIST_PATH)
                    revjson(USER_ID)
                    
                if(command == "3"):
                    revjson(10)
                    print("[*] 请输入想要访问的DATANOTE")
                    try:
                        ensk = getEnSK(10,USER_ID)                         # 获取加密后的CP-ABE密钥EncryptSK
                        # print(ensk)
                        ownpk = getPK(10)                                  # 获取CP-ABE公钥PK
                        ownsk = decryptSK(ensk) 
                        clientServer.send(input("[+] ").encode())
                        enmsg = clientServer.recv(BUFFSIZE)
                        ctk ,sig = getCTK(10,"Data1")                      # 获取CP-ABE密文CT
                        key = decryptCTK(ownpk,ownsk,ctk)                  # 解密CP-ABE密文,得到ABE密钥key
                        pt = DataDecrypt(enmsg,key,sig)
                        print(pt)
                    except:
                        print("[!] 用户" + str(USER_ID) + ", 您无权限访问.")
                if(command == "4"):
                    clientServer.close()
                    break
                
        elif(op == "3"):
            print("[*] 用户已退出")
            sys.exit(0)
        else:
            print("Invalid Operation!")
# 主函数
if __name__ == "__main__":
    duSocketTest()
    # try:
    #     # doIint_REQ(USER_ID,10)
    #     doAccess(10)
    # except:
    #     print("[!] 用户" + str(USER_ID) + ", 您无权限访问.")
