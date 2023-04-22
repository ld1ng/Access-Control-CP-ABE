import os
import time
import json
import libnum
import hmac
import socket
import hashlib
from utilise.cpabe import *
from utilise.KUNode import UserTree
from utilise.myRSA import HandleRSA
import utilise.myAES as AES
from AM import *
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.core.math.pairing import hashPair as extractor
##########################################################################################
USER_ID = 10
PK_PATH = "User"+str(USER_ID)+"/User"+str(USER_ID)+".pub"
SK_PATH = "User"+str(USER_ID)+"/User"+str(USER_ID)+".key"
INFOLIST_PATH = "User"+str(USER_ID)+"/User"+str(USER_ID)+".json"
USER_INFO = dict()
SERVER_ADDRESS = ("127.0.0.1", 12345)
BUFFSIZE = 40960
n_users = 8
height = 3
##########################################################################################
UTree = UserTree(n_users, height)
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

# 初始化过程
def init_do(ownerid):
    global pk,mk
    USER_INFO["key"] = ownerid
    USER_INFO["value"] = {"identify":"DO","dataList":[],"duList":[],"PK":None,"sk":{}}
    (pk, mk) = cpabe.setup()
    USER_INFO["value"]["PK"] = objectToBytes(pk,groupObj).decode()
    initList(INFOLIST_PATH)

# 利用duID向AM请求属性和生成访问策略
def reqAttrs(userid):
    file_path = "User"+str(USER_ID)+"/User"+str(userid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        X, Y = UTree.get_sets()
        userList = getList(file_path)["value"]
        attrList = userList["currentAttrList"]
        roleList = userList["currentRoleList"]
        attrs = attrList + roleList + list(map(str,UTree.get_common(userid,Y)))
        return attrs
    # userList = getList(file_path)["value"]
    # attrList = userList["currentAttrList"]
    # roleList = userList["currentRoleList"]
    # attrs = attrList + roleList + list(map(str,UTree.get_common(userid,Y)))
    # return attrs


# 根据策略生成最终有效访问策略  
# TODO: 加入可撤回版本号
def genPolicy(role, policy, roleattr=None):
    roleset = []; newrolelist=[]
    for i in role:
        roleset += renRoleset()[i]
    roleset = list(set(roleset))
    X, Y = UTree.get_sets()
    if(roleattr):
        RAdict = ATree.roleList
        for j in roleset:
            if(roleattr in RAdict[j]):
                newrolelist.append(j)
        access_policy = policy + " and " + roleOR(newrolelist) + " and (" + " or ".join("%s" %id for id in Y) + ")"
        return access_policy
    else:
        access_policy = policy + " and " + roleOR(roleset) + " and (" + " or ".join("%s" %id for id in Y) + ")"
        return access_policy

# CP-ABE密钥sk加密
def encryptSK(userid,sk,validDate):
    encrypt_sk = []
    update_sk = {}
    sk = objectToBytes(sk,groupObj).decode() # pairs.element to str
    file_path = "User"+str(USER_ID)+"/User"+str(userid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        pk = getList(file_path)["value"]["pk"]
        mrsa = HandleRSA()
        for i in range(0,len(sk),100):
            encrypt_sk.append(mrsa.encrypt(pk, sk[i:i+100]))  # RSA分组进行加密
        update_sk[userid] = list((encrypt_sk,validDate))
        # updateList(INFOLIST_PATH,"sk",update_sk)
        with open(INFOLIST_PATH,"r+") as f:
            userList = json.load(f)
            if(str(userid) in userList["value"]["sk"].keys()):
                for i in userList["value"]["sk"]:
                    if(i == str(userid)):
                        userList["value"]["sk"][i] = update_sk[userid]
            else:
                userList["value"]["sk"].update(update_sk)
            f.seek(0)
            f.truncate()
            json.dump(userList,f)
        f.close()


# 生成密钥key的密文CTK
def genCTK(pk,msg,policy):
    ctk = cpabe.encrypt(pk, msg, policy)
    ctk = objectToBytes(ctk,groupObj).decode()
    print("[*] 成功生成密钥密文CTK" )
    return ctk

# 确认授予密钥SK
def ackSK(userid,ownerid):
    file_path = "User"+str(USER_ID)+"/User"+str(userid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        userList = getList(file_path)["value"]
        askKeyList = userList["askForKey"]
        if(str(ownerid) in askKeyList.keys()):
            askKeyList[str(ownerid)] = "ACCEPT"
        updateList(file_path,"askForKey",askKeyList)

# 元数据上传
def dataUpload(ownerid,datanote,ctk,h):
    file_path = "User"+str(USER_ID)+"/User"+str(ownerid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        userList = getList(file_path)["value"]
        metadata = dict()
        metadata["dataNote"] = datanote
        metadata["hmac"] = h
        metadata["ct"] = ctk
        userList["dataList"].append(metadata)
        updateList(INFOLIST_PATH,"dataList",userList["dataList"])
        print("[*] 元数据上传成功")

# 授予数据访问权限
def ackData(ownerid,userid,dataList):
    ownerfile_path = "User"+str(USER_ID)+"/User"+str(ownerid)+".json"
    userfile_path = "User"+str(USER_ID)+"/User"+str(userid)+".json"
    if(not (os.path.exists(ownerfile_path) and os.path.exists(userfile_path))):
        print("Invalid User!")
        return False
    else:
        ownerList = getList(ownerfile_path)["value"]
        now = time.time()
        if(str(userid) not in ownerList["sk"].keys()):
            attrs = reqAttrs(userid) 
            sk = cpabe.keygen(pk, mk, attrs)  
            encryptSK(userid,sk,time.strftime("%Y-%m-%d",time.localtime(now))) 
            ownerList = getList(ownerfile_path)["value"]
        ownerList["duList"] = [i for i in ownerList["duList"] if time.mktime(time.strptime(i["time"],"%Y-%m-%d")) > now]
        dotemp = dict()
        dotemp["duId"] = userid
        dotemp["dataList"] = dataList
        dotemp["accessState"] = "ACCEPT"
        dotemp["time"] = ownerList["sk"][str(userid)][1]
        ownerList["duList"].append(dotemp)
        updateList(ownerfile_path,"duList",ownerList["duList"])
        userList  = getList(userfile_path)["value"]["askAccessList"]
        for i in range(len(userList)):
            if(userList[i]["askDataList"] == dataList and userList[i]["doId"] == ownerid):
                userList[i]["currentState"] = "AGREE"
        updateList(userfile_path,"askAccessList",userList)
# test   
# def genCTK_test(pk,msg,policy):
#     ctk = cpabe.encrypt(pk, msg, policy)
#     ctk = objectToBytes(ctk,groupObj).decode()
#     with open(CT_PATH,"w") as f:
#         f.write(ctk)
#     return ctk

# 获得明文
def getPT(datanote):
    filename = "User"+str(USER_ID)+"/"+datanote+"_pt.txt"
    if(not os.path.exists(filename)):
        print("Invalid filename!")
        return False
    else:
        with open(filename,"rb") as f:
            pt = f.read()
        f.close()
        return pt

# 数据加密
def DataEncrypt(datanote,msg,key):
    filename = "User"+str(USER_ID)+"/"+datanote+"_ct.txt"
    if(not os.path.exists(filename)):
        print("Invalid filename!")
        return False
    else:
        ct = AES.encrypt(msg,key)
        with open(filename,"wb") as f:
            f.write(ct)
        print("[*] 数据加密完成")
    return ct

# 生成哈希签名
def genHMAC(key,msg):
    mac = hmac.new(key,msg,hashlib.md5)
    return mac.hexdigest()

def revokeUser(userid):
    now = time.time()
    UTree.revoke(userid)
    attrs = reqAttrs(userid)
    sk = cpabe.keygen(pk, mk, attrs)
    encryptSK(userid,sk,time.strftime("%Y-%m-%d",time.localtime(now)))
    print("[*] 用户"+str(userid)+" 权限已撤销")
    # filename = "User"+str(USER_ID)+"/User"+str(userid)+".json"
    # ownerList = getList(INFOLIST_PATH)["value"]["duList"]
    # userList = getList(filename)["value"]["askAccessList"]
    # for i in range(len(ownerList)):
    #     if(ownerList[i]["duId"] == userid):
    #         ownerList[i]["accessState"] = "REVOKE"
    # for j in range(len(userList)):
    #     if(userList[j]["doId"] == USER_ID):
    #         userList[j]["currentState"] = "REVOKE"
    # updateList(INFOLIST_PATH,"duList",ownerList)
    # updateList(filename,"askAccessList",userList)

def main():
    init_do(USER_ID)                                                  # 初始化DO
    acklist = [1,7]
    access_policy = genPolicy(["R1","R5"],Tn(2,"A1","A2","A3"))       # 构造访问策略
    for id in acklist:
        attrs = reqAttrs(id)                                          # 请求获得DU属性集
        sk = cpabe.keygen(pk, mk, attrs)                              # 生成CP-ABE密钥SK
        encryptSK(id,sk,"2022-12-20")                                 # 加密SK生成EncryptSK
        ackSK(id,USER_ID)                                             # 确认授予DU密钥SK
        ackData(USER_ID,id,["Data1"])                                 # 确认授予DU数据访问权限
        print("[*] 用户" + str(id) + " 授权完成")
    key = groupObj.random(GT)                                         # 生成随机ABE密钥key
    ctk = genCTK(pk,key,access_policy)                                # 生成密文CTK
    msg = getPT("Data1");  msg_key =  extractor(key)                  # 消息与密钥
    dataUpload(USER_ID,"Data1", ctk, genHMAC(msg_key,msg))            # 上传元数据
    DataEncrypt("Data1",msg,msg_key)                                  # 数据加密
    revokeUser(1)                                                     # 撤销用户权限

def sendjson(path):
    userList = getList(path)
    mainSocket.send(json.dumps(userList).encode())
    # print(json.dumps(userList).encode())

def revjson(userid):
    data = json.loads(mainSocket.recv(BUFFSIZE).decode())
    path = "User"+str(USER_ID)+"/User"+str(userid)+".json"
    with open(path,"w") as f:
        json.dump(data,f)
    f.close()
    return path

def doSocketTest():
    doSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    doSocket.bind(SERVER_ADDRESS)
    doSocket.listen(3)
    # print(doSocket)
    while True:
        global mainSocket
        print("等待连接...")   
        mainSocket, addr = doSocket.accept()
        REQ_USER_ID = int(mainSocket.recv(BUFFSIZE).decode())
        cmdinfo = '''
        1. 请求CP-ABE密钥
        2. 请求数据访问权限
        3. 数据访问
        4. 返回
        '''
        mainSocket.send(cmdinfo.encode())
        print("\t1. 用户初始化\n\t2. 撤销用户权限\n\t3. 保持原状")
        op = input("[+] ")
        if(op == "1"):
            init_do(USER_ID)
            access_policy = genPolicy(["R1","R5"],Tn(2,"A1","A2","A3"))
            path = revjson(REQ_USER_ID)
            attrs = reqAttrs(REQ_USER_ID) 
            sk = cpabe.keygen(pk, mk, attrs)
            encryptSK(REQ_USER_ID,sk,"2022-12-20")
            key = groupObj.random(GT)        
            ctk = genCTK(pk,key,access_policy)   
            msg = getPT("Data1");  msg_key =  extractor(key)             
            dataUpload(USER_ID,"Data1", ctk, genHMAC(msg_key,msg))         
            enmsg = DataEncrypt("Data1",msg,msg_key)
        elif (op == "2"):
            re_id = input("请选择撤销权限的用户ID\n[+] ")
            revokeUser(int(re_id))
        while True:
            recv_cmd = mainSocket.recv(BUFFSIZE).decode()
            if not recv_cmd:
                print("[!] 未收到任何内容.")
                break
            if(recv_cmd == "1"):
                sendjson(INFOLIST_PATH)
                path = revjson(REQ_USER_ID)
                ackSK(REQ_USER_ID,USER_ID)
                sendjson(path)
                print("[*] 授权CP-ABE密钥")
                
            if(recv_cmd == "2"):
                sendjson(INFOLIST_PATH)
                path = revjson(REQ_USER_ID)
                ackData(USER_ID,REQ_USER_ID,["Data1"])
                sendjson(path)
                print("[*] 授权数据访问权限")
                
            # if(recv_cmd == "3"):
            #     sendjson(INFOLIST_PATH)
                
            if(recv_cmd == "3"):
                sendjson(INFOLIST_PATH)
                if(op != "1"):
                    datanote = mainSocket.recv(BUFFSIZE).decode()
                    filename = "User"+str(USER_ID)+"/"+datanote+"_ct.txt"
                    with open(filename,"rb") as f:
                        enmsg = f.read()
                    f.close()
                mainSocket.send(enmsg)
                print("[*] 数据访问完成")
            if(recv_cmd == "4"):
                print("[*] 用户已退出")
#主函数
if __name__ == "__main__":
    doSocketTest()
    # main()
    
