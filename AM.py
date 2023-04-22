import os
import json
import socket
from utilise.AttrTree import AttrTree
from utilise.cpabe import *
##########################################################################################
USER_ID = 11
INFOLIST_PATH = "datafile/AttrManager.json"
USER_INFO = dict()
n_users = 8
height = 3
ATree = AttrTree(8)
AM_ADDRESS = ("127.0.0.1", 22347)
BUFFSIZE = 40960
##########################################################################################

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

# 初始化AM
def init_am(userid):
    global USER_INFO
    USER_INFO = {"key":userid,"value":{"identify":"AM","attrTree":None,"roleAttrList":None}}
    attrTree = AttrTree(n_users)
    USER_INFO["value"]["attrTree"] = attrTree.Dict
    USER_INFO["value"]["roleAttrList"] = attrTree.roleList
    initList(INFOLIST_PATH)

# 分配用户角色
def ackRole(userid,assignrolelist):
    file_path = "datafile/User"+str(userid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        reqrolelist = getList(file_path)["value"]["roleStateList"]
        for i in assignrolelist:
            if(i in reqrolelist.keys()):
                reqrolelist[i] = 'ACTIVE'
    updateList(file_path,"roleStateList",reqrolelist)

# 分配用户属性
def ackAttr(userid,assignattrlist):
    file_path = "datafile/User"+str(userid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        reqattrlist = getList(file_path)["value"]["attrStateList"]
        for i in assignattrlist:
            if(i in reqattrlist.keys()):
                reqattrlist[i] = 'ACTIVE'
    updateList(file_path,"attrStateList",reqattrlist)

# 激活用户角色
def activeRole(userid,RA):
    file_path = "datafile/User"+str(userid)+".json"
    if(not os.path.exists(file_path)):
        print("Invalid User!")
        return False
    else:
        userList = getList(file_path)["value"]
        askrole = userList["askUserRoleList"]
        rolestate = userList["roleStateList"]
        attrstate = userList["attrStateList"]
        currRole = userList["currentRoleList"]
        currAttr = userList["currentAttrList"]
        currRole.clear()
        currAttr.clear()
        for i in askrole:
            if(i in rolestate.keys() and rolestate[i] == 'ACTIVE'):
                currRole.append(i)
                currAttr = currAttr + RA[i]
        for j in attrstate:
            if(attrstate[j] == 'ACTIVE'):
                currAttr.append(j)

    updateList(file_path,"currentRoleList",currRole)
    updateList(file_path,"currentAttrList",currAttr)
    updateList(file_path,"session",False)

# 返回角色集
def renRoleset():
    ATree.get_roleset()
    return ATree.roleset

def sendjson(path):
    userList = getList(path)
    mainSocket.send(json.dumps(userList).encode())

def revjson(userid):
    data = json.loads(mainSocket.recv(BUFFSIZE).decode())
    path = "datafile/User"+str(userid)+".json"
    with open(path,"w") as f:
        json.dump(data,f)
    f.close()
    return path

def main():
    init_am(USER_ID)
    # ackRole(7,["R6","R7"])
    # ackAttr(7,["A1","A2"])
    # activeRole(7,ATree.roleList)
    ackRole(1,["R1"])
    ackAttr(1,["A1","A3"])
    activeRole(1,ATree.roleList)

def amSocketTest():
    amSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    amSocket.bind(AM_ADDRESS)
    amSocket.listen(3)
    while True:
        print("等待连接...")
        global mainSocket,REQ_USER_ID
        mainSocket, addr = amSocket.accept()
        cmdinfo = '''
    1. 用户初始化
    2. 请求角色
    3. 请求属性
    4. 请求激活角色
    5. 返回
        '''
        mainSocket.send(cmdinfo.encode())
        while True:
            recv_cmd = mainSocket.recv(BUFFSIZE).decode()
            if not recv_cmd:
                print("[!] 未收到任何内容.")
                break
            if(recv_cmd == "1"):
                REQ_USER_ID = int(mainSocket.recv(BUFFSIZE).decode())
                print("[*] 用户"+str(REQ_USER_ID)+",初始化完成")
            if(recv_cmd == "2"):
                path = revjson(REQ_USER_ID)
                print("[*] 用户请求的角色列表为: " + str(getList(path)["value"]["roleStateList"]))
                ackRole(REQ_USER_ID,["R1"])
                print("[*] 用户授权完成")
                sendjson(path)
            if(recv_cmd == "3"):
                path = revjson(REQ_USER_ID)
                ackAttr(REQ_USER_ID,["A1","A3"])
                print("[*] 属性授权完成")
                sendjson(path)
            if(recv_cmd == "4"):
                path = revjson(REQ_USER_ID)
                activeRole(REQ_USER_ID,ATree.roleList)
                print("[*] 用户激活完成")
                sendjson(path)
            if(recv_cmd == "5"):
                print("[*] 用户已退出")

if __name__ == "__main__":
    amSocketTest()
    # main()
