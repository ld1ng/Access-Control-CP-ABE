import numpy as np
class AttrTree:
    # 初始化AttrTree
    def __init__(self, n_users):
        self.n_users = n_users
        self.adjlist = [[None for i in range(self.n_users)] for i in range(self.n_users)]
        self.Dict = {"root":{"parent":None,"child":["R7","R8"]},
        "R1":{"parent":"R4","child":[]},
        "R2":{"parent":"R4","child":[]},
        "R3":{"parent":"R6","child":[]},
        "R4":{"parent":"R7","child":["R1","R2"]},
        "R5":{"parent":"R7","child":[]},
        "R6":{"parent":"R8","child":["R3"]},
        "R7":{"parent":"root","child":["R4","R5"]},
        "R8":{"parent":"root","child":["R6"]}}
        # self.Dict = {"root":{"role":"root","parent":None,"children":[{"role":"R7","parent":"root",
        # "children":[{"role":"R4","parent":"R7","children":[{"role":"R1","parent":"R4","children":[]},
        # {"role":"R2","parent":"R4","children":[]}]},{"role":"R5","parent":"R7","children":[]}]},
        # {"role":"R8","parent":"root","children":[{"role":"R6","parent":"R8",
        # "children":[{"role":"R3","parent":"R6","children":[]}]}]}]}}
        self.roleList = {"R1":["RA1"],"R2":["RA2"],"R3":["RA3"],"R4":["RA4"],"R5":["RA5"],"R6":["RA6"],"R7":["RA7"],"R8":["RA8"]}
        self.roleset = dict()

    # 求可达矩阵
    def reachMatrix(self):
        dict_key = list(self.Dict.keys())
        for i in range(self.n_users):
            self.adjlist[i][i] = 0
            for j in range(self.n_users):
                if(self.Dict[dict_key[i+1]]["parent"]==dict_key[j+1]):
                    self.adjlist[i][j] = 1
                else:
                    self.adjlist[i][j] = 0
        A = np.mat(self.adjlist)
        I = np.identity(len(A))
        newMat = A+I
        oldMat = newMat
        flag = 0
        step = 1
        while flag == 0:
            oldMat = newMat
            newMat = oldMat*(A+I)
            for i in range(len(newMat)):
                for j in range(len(newMat)):
                    if newMat[i, j] >= 1:
                        newMat[i, j] = 1
            step += 1
            if (oldMat == newMat).all():
                flag = 1
                # print(newMat)
                self.adjlist = newMat.tolist()
    
    # 得到角色集
    def get_roleset(self):
        dict_key = list(self.Dict.keys())
        self.reachMatrix()
        for x in range(self.n_users):
            self.roleset[dict_key[x+1]] = []
        for k in range(self.n_users):
            for i in range(self.n_users):
                if(self.adjlist[i][k] == 1):
                    self.roleset[dict_key[i+1]].append(dict_key[k+1])

    # 添加角色属性
    def addRoleAttr(self,ra,r):
        for i in self.Dict:
            if(i == r):
                self.roleList[i].append(ra)
                break
        return False
    
    # 删除角色属性
    def deleteRoleAttr(self,ra,r):
        for i in self.roleList[r]:
            if(i == ra):
                self.roleList[r].remove(ra)
        return False
    
    # 构造继承关系
    def add_inherit(self,parent_r,child_r):
        if(parent_r not in self.Dict.keys() or child_r not in self.Dict.keys()):
            return False
        if(not self.Dict[child_r]["parent"]):
            self.Dict[parent_r]["child"].append(child_r)
            self.Dict[child_r]["parent"] = parent_r
        else:
            self.Dict[self.Dict[child_r]["parent"]]["child"].remove(child_r)
            self.Dict[parent_r]["child"].append(child_r)
            self.Dict[child_r]["parent"] = parent_r
    
    # 删除构造关系
    def del_inherit(self,parent_r,child_r):
        if(parent_r not in self.Dict.keys() or child_r not in self.Dict.keys()):
            return False
        if(not self.Dict[parent_r]["parent"]):
            return False
        else:
            self.Dict[parent_r]["child"].remove(child_r)
            self.Dict[self.Dict[parent_r]["parent"]]["child"].append(child_r)
            self.Dict[child_r]["parent"] = self.Dict[parent_r]["parent"]

# 主函数
# if __name__ == "__main__":
    # a = AttrTree(8)
    # a.reachMatrix()
    # a.get_roleset()
    # a.addRoleAttr("RA3","R2")
    # print(a.roleList)
    # a.deleteRoleAttr("RA3","R2")
    # print(a.roleList)
    # print(a.adjlist)
