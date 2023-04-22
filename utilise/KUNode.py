class UserTree:
    # 初始化UserTree
    def __init__(self, n_users, h=1):
        """
                    7
                5       6
              1   2   3   4
        node = [lchild,rchild,parent,"RED",None]
        """
        self.height = h
        self.root = 2**(h+1)-1
        self.Dict = dict()
        self.RL = []
        self.__build_tree()
        self.Dict[self.root][3] = "BLUE"
        self.n_users = n_users

    # 构造UserTree
    def __build_tree(self):
        count = 2**self.height + 1
        height = self.height - 1
        for i in range(1, 2**self.height + 1):
            self.Dict[i] = [None, None, None, "RED", None] # 初始化叶子节点
        lcount = 1
        # print(self.Dict)
        while count != self.root+1:
            flow = lcount
            #print(flow)
            while flow - lcount != 2**(height+1):
                self.Dict[count] = [flow, flow + 1, None, "RED", None]
                self.Dict[flow][2] = count
                self.Dict[flow + 1][2] = count
                count += 1
                flow += 2
                # print("count = %d flow = %d lcount = %d" %(count, flow, lcount))
            height -= 1
            lcount = flow 
    # 撤销用户权限
    def revoke(self, user):
        assert user <= 2**self.height, "User not present"
        assert user <= self.n_users, "User not present"
        curr_node = self.Dict[user]
        assert (curr_node[0], curr_node[1]) == (None, None) # 保证是叶子节点
        curr_node[3] = "BLACK"
        curr_parent = curr_node[2]
        self.RL.append(user) 

        while curr_parent != None:
            curr_node = curr_parent
            node = self.Dict[curr_node]
            node[3] = "BLACK"
            if self.Dict[node[0]][3] == "RED":
                self.Dict[node[0]][3] = "BLUE"
            elif self.Dict[node[1]][3] == "RED":
                self.Dict[node[1]][3] = "BLUE"
            curr_parent = node[2]

    # 获取Cover(R) 和 已撤销列表
    def get_sets(self):
        '''
        Y = Cover(R)  X = R(已撤销)
        '''
        X, Y = list(), list()
        for node in self.Dict:
            q = self.Dict[node]
            if q[3] == "BLACK":
                X.append(node)
            elif q[3] == "BLUE":
                Y.append(node)
        return X, Y

    # 计算某节点UserTree路径
    def Path(self, user):
        assert user <= 2**self.height, "User not present"
        assert user <= self.n_users, "User not present"
        curr_node = self.Dict[user]
        assert (curr_node[0], curr_node[1]) == (None, None) # 叶子节点
        path = [user]
        parent = curr_node[2]

        while parent != None:
            curr_node = parent
            path.append(curr_node)
            parent = self.Dict[curr_node][2]
        return path

    # 添加用户
    def addUser(self, nos=1):
        assert self.n_users + nos <= 2**self.height, "Can't add so many users"
        self.n_users += nos

    # 得到撤销列表
    def getRL(self):
        return self.RL
    
    # 获取Cover(R)与路径交集
    def get_common(self,user,Y):
        path = set(self.Path(user))
        return list(path.intersection(set(Y)))
        
# if __name__ == "__main__":
#     a = RevokeTree(5, 3)
#     print(a.Dict)
#     X, Y = a.get_sets()
#     path = set(a.Path(2))
#     common = path.intersection(set(Y)) # 求交集
#     print("Common ", common)
#     for w in common:
#         print(int(w))
#     print("X = {} \nY = {}".format(X, Y))
#     a.revoke(3)
#     X, Y = a.get_sets()
#     print("X = {} \nY = {}".format(X, Y))
#     a.addUser()
#     a.revoke(6)
#     path3 = a.Path(3)
#     print("Path for 3 =", path3)
#     path6 = a.Path(6)
#     print("Path for 6 =", path6)
#     X, Y = a.get_sets()
#     print("X = {} \nY = {}".format(X, Y))
#     # a.addUser(3)
#     Revoke_List = a.getRL()
#     print(Revoke_List)