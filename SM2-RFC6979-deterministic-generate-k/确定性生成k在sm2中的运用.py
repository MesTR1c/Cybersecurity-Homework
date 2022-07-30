import random
import hashlib
import hmac
# 选择素域，设置椭圆曲线参数
default_ecc_table = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'\
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}
class CryptSM2(object):##优化后的sm2加密类
    def __init__(self, private_key, public_key, ecc_table=default_ecc_table):
        self.private_key = private_key
        self.public_key = public_key
        self.para_len = len(ecc_table['n'])
        self.ecc_a3 = (
            int(ecc_table['a'], base=16) + 3) % int(ecc_table['p'], base=16)
        self.ecc_table = ecc_table
        self.lstg=self.kpub(ecc_table['g'])
        self.lstpk=self.kpub(public_key)
    def er(self,n):##分解2次方
        k=0
        while n:
            n,r=divmod(n,2)
            if r:
                n=n*2+r
                break
            k=k+1
        return n,k
    def san(self,n):##分解三次方
        k=0
        while n:
            n,r=divmod(n,3)
            if r:
                n=n*3+r
                break
            k=k+1
        return n,k
    def resolve(self,n):##分解
        lst=[]
        for i in range(100):
            lst.append([0,0,0])
        k=0
        numlst=(-1,1,-5,5,-7,7)
        
        numlst1=(-1,1)
        n,k0=self.er(n)
        n,k1=self.san(n)
        lst[k][0]=k0
        lst[k][1]=k1
        while n>1:
            numlstlst={-1:(0,0,0),1:(0,0,0),-5:(0,0,0),5:(0,0,0),-7:(0,0,0),7:(0,0,0)}
            maxnum=(n,0)
            if n==1:
                break
            if n>7:
                for i in numlst:
                    n1=n+i
                    n1,k0=self.er(n1)
                    n1,k1=self.san(n1)
                    numlstlst[i]=(n1,k0,k1)
                    if n1==1:
                        maxnum=(n1,i)
                        break
                    else:
                        if maxnum[0]>n1:
                            maxnum=(n1,i)
            else:
                for i in numlst1:
                    n1=n+i
                    n1,k0=self.er(n1)
                    n1,k1=self.san(n1)
                    numlstlst[i]=(n1,k0,k1)
                    if n1==1:
                        maxnum=(n1,i)
                        break
                    else:
                        if maxnum[0]>n1:
                            maxnum=(n1,i)
            n=numlstlst[maxnum[1]][0]
            lst[k][2]=maxnum[1]
            k=k+1
            lst[k][0]=numlstlst[maxnum[1]][1]
            lst[k][1]=numlstlst[maxnum[1]][2]
        return lst
    def resolve1(self,n):##分解随机策略
        lst=[]
        for i in range(100):
            lst.append([0,0,0])
        k=0
        lst1=[7,11,13,17,19,23]
        a=lst1[random.randint(0,5)]
        numlst=(-1,1,-5,5,a,-a)
        numlst1=(-1,1)
        n,k0=self.er(n)
        n,k1=self.san(n)
        lst[k][0]=k0
        lst[k][1]=k1
        while n>1:
            numlstlst={-1:(0,0,0),1:(0,0,0),-5:(0,0,0),5:(0,0,0),-a:(0,0,0),a:(0,0,0)}
            maxnum=(n,0)
            if n==1:
                break
            if n>a:
                for i in numlst:
                    n1=n+i
                    n1,k0=self.er(n1)
                    n1,k1=self.san(n1)
                    numlstlst[i]=(n1,k0,k1)
                    if n1==1:
                        maxnum=(n1,i)
                        break
                    else:
                        if maxnum[0]>n1:
                            maxnum=(n1,i)
            else:
                for i in numlst1:
                    n1=n+i
                    n1,k0=self.er(n1)
                    n1,k1=self.san(n1)
                    numlstlst[i]=(n1,k0,k1)
                    if n1==1:
                        maxnum=(n1,i)
                        break
                    else:
                        if maxnum[0]>n1:
                            maxnum=(n1,i)
            n=numlstlst[maxnum[1]][0]
            lst[k][2]=maxnum[1]
            k=k+1
            lst[k][0]=numlstlst[maxnum[1]][1]
            lst[k][1]=numlstlst[maxnum[1]][2]
        return lst
    def resolve2(self,n):##普通naf分解
        lst=[]
        for i in range(100):
            lst.append([0,0,0])
        k=0
        numlst=(-1,1,-5,5,-7,7)
        
        numlst1=(-1,1)
        n,k0=self.er(n)
        n,k1=self.san(n)
        lst[k][0]=k0
        lst[k][1]=k1
        while n>1:
            numlstlst={-1:(0,0,0),1:(0,0,0),-5:(0,0,0),5:(0,0,0),-7:(0,0,0),7:(0,0,0)}
            maxnum=(n,0)
            if n==1:
                break
            if n>7:
                for i in numlst:
                    n1=n+i
                    n1,k0=self.er(n1)
                    n1,k1=self.san(n1)
                    numlstlst[i]=(n1,k0,k1)
                    if n1==1:
                        maxnum=(n1,i)
                        break
                    else:
                        if maxnum[0]>n1:
                            maxnum=(n1,i)
            else:
                for i in numlst1:
                    n1=n+i
                    n1,k0=self.er(n1)
                    n1,k1=self.san(n1)
                    numlstlst[i]=(n1,k0,k1)
                    if n1==1:
                        maxnum=(n1,i)
                        break
                    else:
                        if maxnum[0]>n1:
                            maxnum=(n1,i)
            n=numlstlst[maxnum[1]][0]
            lst[k][2]=maxnum[1]
            k=k+1
            lst[k][0]=numlstlst[maxnum[1]][1]
            lst[k][1]=numlstlst[maxnum[1]][2]
        return lst
    def kpub(self,data):##用于生成预计算表，对于传入的data，每一个生成一个字典，键值就是字符
        k=int(self.ecc_table['p'],16)
        a,b=divmod(int(data[64:128],16),k)
        b=k-b
        form = '%%0%dx' % self.para_len
        str1=data[0:64]+form%b
        lst={'p1':data,
             'p-1':str1,
             'p5':self._kg(5,data),
             'p-5':self._kg(5,str1),
             'p7':self._kg(7,data),
             'p-7':self._kg(7,str1),
             'p11':self._kg(11,data),
             'p13':self._kg(13,data),
             'p17':self._kg(17,data),
             'p19':self._kg(19,data),
             'p23':self._kg(23,data),
             'p-11':self._kg(11,str1),
             'p-13':self._kg(13,str1),
             'p-17':self._kg(17,str1),
             'p-19':self._kg(19,str1),
             'p-23':self._kg(23,str1)
             }
        return lst
    def _kg(self, k, Point):  # gmssl库中本来的kP运算，这里仅用来生成预计算表，几乎不耗时间
        
        Point = '%s%s' % (Point, '1')
        mask_str = '8'
        
        for i in range(self.para_len - 1):
            mask_str += '0'
        mask = int(mask_str, 16)
        Temp = Point
        flag = False
        for n in range(self.para_len * 4):
            if (flag):
                ##print('Temp长度为：',len(Temp),'   ','Point长度为：',len(Point))
                Temp = self._double_point(Temp)
            if (k & mask) != 0:
                if (flag):
                    
                    Temp = self._add_point(Temp, Point)
                else:
                    flag = True
                    Temp = Point
            k = k << 1
        return self._convert_jacb_to_nor(Temp)
    def _kg2(self, k, Point):  # 基本的kg运算，对于传入的g，预计算表，采用扩展双基链的树形方法进行分解和计算，在这里仅使用了双基链和树形算法，可以扩展成多基链
        
        Point = '%s%s' % (Point, '1')
        temp = Point
        lstfj=self.resolve(k)
        for k in range(100):
            i=99-k
            for m in range(3):
                j=2-m
                if j==0 :
                    for k0 in range(lstfj[i][j]):
                        temp=self._double_point2(temp)
                if j==1:
                    for k1 in range(lstfj[i][j]):
                        temp=self._trible_point(temp)
                if j==2 and lstfj[i][j]:
                    index='p'+str(-lstfj[i][j])
                    point2=self.lstg[index]
                    temp=self._add_point(temp,point2)
        return self._convert_jacb_to_nor(temp)
    def _kg2_2(self, k, Point):  # 基本的kg运算，对于传入的g，预计算表，采用随机策略进行分解和计算，在这里仅使用了双基连和树形算法，可以扩展成多基链
        
        Point = '%s%s' % (Point, '1')
        temp = Point
        lstfj=self.resolve1(k)
        for k in range(100):
            i=99-k
            for m in range(3):
                j=2-m
                if j==0 :
                    for k0 in range(lstfj[i][j]):
                        temp=self._double_point2(temp)
                if j==1:
                    for k1 in range(lstfj[i][j]):
                        temp=self._trible_point(temp)
                if j==2 and lstfj[i][j]:
                    index='p'+str(-lstfj[i][j])
                    point2=self.lstg[index]
                    temp=self._add_point(temp,point2)
        return self._convert_jacb_to_nor(temp)
    def _kp2(self, k, Point):  ##上述树形算法的变形，用于加快计算传入的k*publick_key
        
        Point = '%s%s' % (Point, '1')
        temp = Point
        lstfj=self.resolve(k)
        for k in range(100):
            i=99-k
            for m in range(3):
                j=2-m
                if j==0 :
                    for k0 in range(lstfj[i][j]):
                        temp=self._double_point2(temp)
                if j==1:
                    for k1 in range(lstfj[i][j]):
                        temp=self._trible_point(temp)
                if j==2 and lstfj[i][j]:
                    index='p'+str(-lstfj[i][j])
                    point2=self.lstpk[index]
                    temp=self._add_point(temp,point2)
        return self._convert_jacb_to_nor(temp)
    def _kp2_2(self, k, Point):  ##上述随机算法的变形，用于加快计算传入的k*publick_key
        
        Point = '%s%s' % (Point, '1')
        temp = Point
        lstfj=self.resolve1(k)
        for k in range(100):
            i=99-k
            for m in range(3):
                j=2-m
                if j==0 :
                    for k0 in range(lstfj[i][j]):
                        temp=self._double_point2(temp)
                if j==1:
                    for k1 in range(lstfj[i][j]):
                        temp=self._trible_point(temp)
                if j==2 and lstfj[i][j]:
                    index='p'+str(-lstfj[i][j])
                    point2=self.lstpk[index]
                    temp=self._add_point(temp,point2)
        return self._convert_jacb_to_nor(temp)
    def _kp(self, k, Point,data):  # # 上述树形算法的变形，用于加快计算传入的k*private_key
        
        Point = '%s%s' % (Point, '1')
        temp = Point
        lstfj=self.resolve(k)
        lstpr=self.kpub(data)
        for k in range(100):
            i=99-k
            for m in range(3):
                j=2-m
                if j==0 :
                    for k0 in range(lstfj[i][j]):
                        temp=self._double_point2(temp)
                if j==1:
                    for k1 in range(lstfj[i][j]):
                        temp=self._trible_point(temp)
                if j==2 and lstfj[i][j]:
                    index='p'+str(-lstfj[i][j])
                    point2=lstpr[index]
                    temp=self._add_point(temp,point2)
        return self._convert_jacb_to_nor(temp)
    def _kp_2(self, k, Point,data):  # # 上述随机算法的变形，用于加快计算传入的k*private_key
        
        Point = '%s%s' % (Point, '1')
        temp = Point
        lstfj=self.resolve1(k)
        lstpr=self.kpub(data)
        for k in range(100):
            i=99-k
            for m in range(3):
                j=2-m
                if j==0 :
                    for k0 in range(lstfj[i][j]):
                        temp=self._double_point2(temp)
                if j==1:
                    for k1 in range(lstfj[i][j]):
                        temp=self._trible_point(temp)
                if j==2 and lstfj[i][j]:
                    index='p'+str(-lstfj[i][j])
                    point2=lstpr[index]
                    temp=self._add_point(temp,point2)
        return self._convert_jacb_to_nor(temp)
    def _double_point(self, Point):  # 原库中2倍点
        l = len(Point)
        len_2 = 2 * self.para_len
        if l< self.para_len * 2:
            return None
        else:
            x1 = int(Point[0:self.para_len], 16)
            y1 = int(Point[self.para_len:len_2], 16)
            if l == len_2:
                z1 = 1
            else:
                z1 = int(Point[len_2:], 16)

            T6 = (z1 * z1) % int(self.ecc_table['p'], base=16)
            T2 = (y1 * y1) % int(self.ecc_table['p'], base=16)
            T3 = (x1 + T6) % int(self.ecc_table['p'], base=16)
            T4 = (x1 - T6) % int(self.ecc_table['p'], base=16)
            T1 = (T3 * T4) % int(self.ecc_table['p'], base=16)
            T3 = (y1 * z1) % int(self.ecc_table['p'], base=16)
            T4 = (T2 * 8) % int(self.ecc_table['p'], base=16)
            T5 = (x1 * T4) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * 3) % int(self.ecc_table['p'], base=16)
            T6 = (T6 * T6) % int(self.ecc_table['p'], base=16)
            T6 = (self.ecc_a3 * T6) % int(self.ecc_table['p'], base=16)
            T1 = (T1 + T6) % int(self.ecc_table['p'], base=16)
            z3 = (T3 + T3) % int(self.ecc_table['p'], base=16)
            T3 = (T1 * T1) % int(self.ecc_table['p'], base=16)
            T2 = (T2 * T4) % int(self.ecc_table['p'], base=16)
            x3 = (T3 - T5) % int(self.ecc_table['p'], base=16)

            if (T5 % 2) == 1:
                T4 = (T5 + ((T5 + int(self.ecc_table['p'], base=16)) >> 1) - T3) % int(self.ecc_table['p'], base=16)
            else:
                T4 = (T5 + (T5 >> 1) - T3) % int(self.ecc_table['p'], base=16)

            T1 = (T1 * T4) % int(self.ecc_table['p'], base=16)
            y3 = (T1 - T2) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (x3, y3, z3)
    def _double_point2(self, Point):  # 优化过后的两倍点，时间降了一半
        l = len(Point)
        len_2 = 2 * self.para_len
        if l< self.para_len * 2:
            return None
        else:
            x1 = int(Point[0:self.para_len], 16)
            y1 = int(Point[self.para_len:len_2], 16)
            if l == len_2:
                z1 = 1
            else:
                z1 = int(Point[len_2:], 16)

            C = (z1 * z1) % int(self.ecc_table['p'], base=16)
            B = (y1 * y1) % int(self.ecc_table['p'], base=16)
            T = 3*((x1+C)*(x1-C)) % int(self.ecc_table['p'], base=16)
            ##u = (4*(x1+B)*(x1+B)-A-B*B) % int(self.ecc_table['p'], base=16)
            U = (B*x1) % int(self.ecc_table['p'], base=16)
            x3 = (T*T-8*U) % int(self.ecc_table['p'], base=16)
            y3 = (T*(4*U-x3) - 8*B*B) % int(self.ecc_table['p'], base=16)
            z3 = (pow((y1+z1),2)-C-B) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (x3, y3, z3)
    def _trible_point(self, Point): #新加入的三倍点运算
        l = len(Point)
        len_2 = 2 * self.para_len
        if l< self.para_len * 2:
            return None
        else:
            x1 = int(Point[0:self.para_len], 16)
            y1 = int(Point[self.para_len:len_2], 16)
            if l == len_2:
                z1 = 1
            else:
                z1 = int(Point[len_2:], 16)

            C = (z1 * z1) % int(self.ecc_table['p'], base=16)
            B = (y1 * y1) % int(self.ecc_table['p'], base=16)
            T = 3*((x1+C)*(x1-C)) % int(self.ecc_table['p'], base=16)
            ##u = (4*(x1+B)*(x1+B)-A-B*B) % int(self.ecc_table['p'], base=16)
            U = (B*x1) % int(self.ecc_table['p'], base=16)
            TT=pow(T,2) % int(self.ecc_table['p'], base=16)
            a = (T*T-12*U) % int(self.ecc_table['p'], base=16)
            aa = pow(a,2) % int(self.ecc_table['p'], base=16)
            BB =(16*pow(B,2)) % int(self.ecc_table['p'], base=16)
            b = (pow((T+a),2) - TT -aa+BB) % int(self.ecc_table['p'], base=16)
            x3 = (4*(4*B*b+x1*aa)) % int(self.ecc_table['p'], base=16)
            y3 = (8*y1*((b+BB)*b-a*aa)) % int(self.ecc_table['p'], base=16)
            z3 = (pow((a+z1),2)-aa-C) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (x3, y3, z3)
    def _add_point(self, P1, P2):  # 点加函数，P2点为仿射坐标即z=1，P1为Jacobian加重射影坐标
        len_2 = 2 * self.para_len
        l1 = len(P1)
        l2 = len(P2)
        if (l1 < len_2) or (l2 < len_2):
            return None
        else:
            X1 = int(P1[0:self.para_len], 16)
            Y1 = int(P1[self.para_len:len_2], 16)
            if (l1 == len_2):
                Z1 = 1
            else:
                Z1 = int(P1[len_2:], 16)
            x2 = int(P2[0:self.para_len], 16)
            y2 = int(P2[self.para_len:len_2], 16)

            T1 = (Z1 * Z1) % int(self.ecc_table['p'], base=16)
            T2 = (y2 * Z1) % int(self.ecc_table['p'], base=16)
            T3 = (x2 * T1) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * T2) % int(self.ecc_table['p'], base=16)
            T2 = (T3 - X1) % int(self.ecc_table['p'], base=16)
            T3 = (T3 + X1) % int(self.ecc_table['p'], base=16)
            T4 = (T2 * T2) % int(self.ecc_table['p'], base=16)
            T1 = (T1 - Y1) % int(self.ecc_table['p'], base=16)
            Z3 = (Z1 * T2) % int(self.ecc_table['p'], base=16)
            T2 = (T2 * T4) % int(self.ecc_table['p'], base=16)
            T3 = (T3 * T4) % int(self.ecc_table['p'], base=16)
            T5 = (T1 * T1) % int(self.ecc_table['p'], base=16)
            T4 = (X1 * T4) % int(self.ecc_table['p'], base=16)
            X3 = (T5 - T3) % int(self.ecc_table['p'], base=16)
            T2 = (Y1 * T2) % int(self.ecc_table['p'], base=16)
            T3 = (T4 - X3) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * T3) % int(self.ecc_table['p'], base=16)
            Y3 = (T1 - T2) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (X3, Y3, Z3)
    def _convert_jacb_to_nor(self, Point): # Jacobian加重射影坐标转换成仿射坐标
        
        len_2 = 2 * self.para_len
        x = int(Point[0:self.para_len], 16)
        y = int(Point[self.para_len:len_2], 16)
        z = int(Point[len_2:], 16)
        z_inv = pow(z, int(self.ecc_table['p'], base=16) - 2, int(self.ecc_table['p'], base=16))
        z_invSquar = (z_inv * z_inv) % int(self.ecc_table['p'], base=16)
        z_invQube = (z_invSquar * z_inv) % int(self.ecc_table['p'], base=16)
        x_new = (x * z_invSquar) % int(self.ecc_table['p'], base=16)
        y_new = (y * z_invQube) % int(self.ecc_table['p'], base=16)
        z_new = (z * z_inv) % int(self.ecc_table['p'], base=16)
        if z_new == 1:
            form = '%%0%dx' % self.para_len
            form = form * 2
            
            return form % (x_new, y_new)
        else:
            return None
    
    def verify(self, Sign, data):
        # 验签函数，sign签名r||s，E消息hash，public_key公钥
        r = int(Sign[0:self.para_len], 16)
        s = int(Sign[self.para_len:2*self.para_len], 16)
        e = int(data.hex(), 16)
        t = (r + s) % int(self.ecc_table['n'], base=16)
        if t == 0:
            return 0

        P1 = self._kg2(s, self.ecc_table['g'])
        P2 = self._kp2(t, self.public_key)
        # print(P1)
        # print(P2)
        if P1 == P2:
            P1 = '%s%s' % (P1, 1)
            P1 = self._double_point(P1)
        else:
            P1 = '%s%s' % (P1, 1)
            P1 = self._add_point(P1, P2)
            P1 = self._convert_jacb_to_nor(P1)

        x = int(P1[0:self.para_len], 16)
        return (r == ((e + x) % int(self.ecc_table['n'], base=16)))
    def sign(self, data):  # 签名函数, data消息的hash，private_key私钥，K随机数，均为16进制字符串
        E = data.hex() # 消息转化为16进制字符串
        e = int(E, 16)

        d = int(self.private_key, 16)
        k = self.generete_deterministic_k(E)

        P1 = self._kg2(k, self.ecc_table['g'])

        x = int(P1[0:self.para_len], 16)
        R = ((e + x) % int(self.ecc_table['n'], base=16))
        if R == 0 or R + k == int(self.ecc_table['n'], base=16):
            return None
        d_1 = pow(d+1, int(self.ecc_table['n'], base=16) - 2, int(self.ecc_table['n'], base=16))
        S = (d_1*(k + R) - R) % int(self.ecc_table['n'], base=16)
        if S == 0:
            return None
        else:
            return '%064x%064x' % (R,S)
    def hash_data(self,data, hash_function = 'sha256'):
      hash_function = getattr(hashlib, hash_function)
      data = data.encode('utf-8')
      return hash_function(data).hexdigest()
    def generete_deterministic_k(self,message):
      private_key=self.private_key
      n=self.ecc_table["n"]
      h1=self.hash_data(message)
      #print(h1)
      V=""
      for i in range(32):
        V=V+"01"
      #print(V,V.encode())
      K=""
      for i in range(32):
        K=K+"00"
      #print(K,len(K))
      K_msg=V+"00"+private_key+h1
      K=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(K_msg),digestmod=hashlib.sha256).hexdigest()
      V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
      V_msg=V+"01"+private_key+h1
      K=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V_msg),digestmod=hashlib.sha256).hexdigest()
      V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
      flag=False
      while(flag==False):
        #print("111")
        T=""
        tlen=0
        qlen=int(n,16).bit_length()
        while(tlen<qlen):
          V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
          T=T+V
          tlen=int(T,16).bit_length()
        k_lower=int(T,16)
        if k_lower>=1 and k_lower<=int(n,16)-1:
          flag=True
        else:
          K=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V+"00"),digestmod=hashlib.sha256).hexdigest()
          V=hmac.new(key=bytes.fromhex(K),msg=bytes.fromhex(V),digestmod=hashlib.sha256).hexdigest()
      print("生成的k为：",k_lower)
      return k_lower


private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

sm2_crypt = CryptSM2(
    public_key=public_key, private_key=private_key)
#数据和加密后数据为bytes类型



data = "Feng Xiangdi" 
print('待签名消息为：',data)
print("私钥为：",private_key)
data_1=data.encode()# bytes类型
sign = sm2_crypt.sign(data_1) #  16进制
print('签名值的16进制表示为:',sign)
assert sm2_crypt.verify(sign, data_1) #  16进制
print("验签成功！")