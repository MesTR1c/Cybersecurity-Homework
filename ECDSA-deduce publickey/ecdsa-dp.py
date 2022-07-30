import random
import hashlib
import math
# 选择素域，设置椭圆曲线参数
default_ecc_table = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'\
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}
class ecdsa(object):
    def __init__(self, private_key, public_key, ecc_table=default_ecc_table):
        self.private_key = private_key
        self.public_key = public_key
        self.para_len = len(ecc_table['n'])
        self.ecc_a3 = (
            int(ecc_table['a'], base=16) + 3) % int(ecc_table['p'], base=16)
        self.ecc_table = ecc_table
        self.lstg=self.kpub(ecc_table['g'])
        #print(self.lstg["p1"][64:128])
        #print(self.lstg["p-1"][64:128])
        #print(self.ecc_table["p"])
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
        n=self.ecc_table["n"]
        n=int(n,16)
        if k>n:
          k=k%n
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
    def hash_data(self,data, hash_function = 'sha256'):
      hash_function = getattr(hashlib, hash_function)
      data = data.encode('utf-8')
      return hash_function(data).hexdigest()
    def gcd(self,a,b):
        while a!=0:
            a,b = b%a,a
        return b
    def findModReverse(self,a,m):#这个扩展欧几里得算法求模逆
        if self.gcd(a,m)!=1:
            return None
        u1,u2,u3 = 1,0,a
        v1,v2,v3 = 0,1,m
        while v3!=0:
            q = u3//v3
            v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
        return u1%m
    def sign(self,msg):
      e=self.hash_data(msg)#msg是str
      z=e #两个都是256bit
      r=0
      s=0
      while(r==0 or s==0):
        k=random.randint(1,int(self.ecc_table["n"],16)-1)
        p=self._kg2(k,self.ecc_table["g"])
        r=divmod(int(p[0:64],16),int(self.ecc_table["n"],16))[1]
        t=self.findModReverse(k,int(self.ecc_table["n"],16))
        s=divmod(t*(int(z,16)+r*int(self.private_key,16)),int(self.ecc_table["n"],16))[1]
      #print(self._kg2(k,self.ecc_table["g"]))
      #print(len(self._kg2(k,self.ecc_table["g"])))
      #print(p)
      x1=p[0:64]
      y1=p[64:128]
      #print(x1)
      #print(y1)
      if int(x1,16)==r:
        flag0=0
      else:
        flag0=1
      #print(flag0)
      y1_ten=int(y1,16)
      #print(y1_ten)
      #temp=divmod(pow(y1_ten,3)+y1_ten*int(self.ecc_table["a"],16)+int(self.ecc_table["b"],16),int(self.ecc_table["p"],16))[1]
      #print(temp)
      if y1_ten%2==0:
        flag1=0
      else:
        flag1=1
      flag=str(flag0)+str(flag1)## flag 可以用2bit表示 一个表示x1和n大小，一个表示y1的奇偶性
      #print(self._kg2(s*k,self.ecc_table["g"]))
      #zG=self._kg2(int(self.hash_data(msg),16)%int(self.ecc_table["n"],16),self.ecc_table["g"])
      #print(zG)
      x1_ten=int(x1,16)
      temp=divmod(pow(x1_ten,3)+x1_ten*int(self.ecc_table["a"],16)+int(self.ecc_table["b"],16),int(self.ecc_table["p"],16))[1]
      #print(temp)
      n=int(self.ecc_table["n"],16)
      r_1=self.findModReverse(r,n)
      u1=n-(int(z,16)*r_1)%n
      #print(u1)
      u1G=self._kg2(u1,self.ecc_table["g"])
      R=self._kg2(k,self.ecc_table["g"])
      u2=(s*r_1)%n
      #print(u2)
      u2R=self._kg(u2,R)
      final=self._add_point(u1G,u2R)
      #print(self._convert_jacb_to_nor(final))
      return (r,s,flag)
    def recoverpub(self,r,s,flag,msg):
      if r>=int(self.ecc_table["n"],16) or s>=int(self.ecc_table["n"],16):  #验证 r 和 s 是整数 [1，n-1] 。如果不是，则签名无效。
        print("输入的r和s大于n的值，输入错误")
        return False
      if flag[0]=='0':
        #print(111)
        x1=r
      else:
        #print(111)
        x1=r+int(self.ecc_table["n"],16)
      #print(hex(x1)[2:])
      temp=divmod(pow(x1,3)+x1*int(self.ecc_table["a"],16)+int(self.ecc_table["b"],16),int(self.ecc_table["p"],16))[1] #得到的是y方，用飞马小定理
      #print(temp)
      p=int(self.ecc_table["p"],16)
      power=(p+1)//4
      y1=pow(temp,power,p)
      y1_jiou=y1%2
      if str(y1_jiou)==flag[1]:
        pass
      else:
        #print(111)
        y1=p-y1
      #print(hex(y1)[2:])
      n=int(self.ecc_table["n"],16)
      r_1=self.findModReverse(r,n)
      #print(r_1)
      x1_hex=hex(x1)[2:]
      #print(len(x1_hex))
      buchong=64-len(x1_hex)
      for i in range(buchong):
        x1_hex="0"+x1_hex
      y1_hex=hex(y1)[2:]
      #print(len(y1_hex))
      buchong1=64-len(y1_hex)
      for i in range(buchong1):
        y1_hex="0"+y1_hex
      kG=x1_hex+y1_hex
      #print(kG)
      #print(len(kG))
      skG=self._kg(s,kG)
      #print(skG)
      zG=self._kg2(int(self.hash_data(msg),16)%n,self.ecc_table["g"])
      a,b=divmod(int(zG[64:128],16),p)
      b=p-b
      zG_1=zG[0:64]+hex(b)[2:]
      #print(zG)
      #print(zG_1)
      #print(self._convert_jacb_to_nor(self._add_point(zG,zG_1)))
      temp2=self._add_point(skG,zG_1)
      temp2=self._convert_jacb_to_nor(temp2)
      #print(temp2)
      pub=self._kg(r_1,temp2)
      print("恢复出来的公钥为：",pub)
      print("初始公钥为：",self.public_key)
      if(int(pub,16)==int(self.public_key,16)):
        print("恢复成功")
      else:
        print("r:",r,"s:",s,"flag:",flag,"msg:",msg)
      return pub
    def verify(self,r,s,flag,msg):
      if r>=int(self.ecc_table["n"],16) or s>=int(self.ecc_table["n"],16):  #验证 r 和 s 是整数 [1，n-1] 。如果不是，则签名无效。
        print("输入的r和s大于n的值，输入错误")
        return False
      e=self.hash_data(msg)#msg是str
      z=e #两个都是256bit
      n=int(self.ecc_table["n"],16)
      s_1=self.findModReverse(s,n)
      u1=(int(z,16)*s_1)%n
      u2=(r*s_1)%n
      pub=self.recoverpub(r,s,flag,msg)
      #print(pub)
      u1G=self._kg2(u1,self.ecc_table["g"])
      u2P=self._kg(u2,pub)
      final=self._add_point(u1G,u2P)
      final=self._convert_jacb_to_nor(final)
      x1=int(final[0:64],16)
      if(r==x1%n):
        print("")
        print("发送信息为  r:",r,"s:",s,"flag:",flag,"msg:",msg)
        print("验签成功")





private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'


ed_crypt = ecdsa(
    public_key=public_key, private_key=private_key)

r,s,flag=ed_crypt.sign("Feng Xiangdi")
#print(r,s,flag)
ed_crypt.verify(r,s,flag,"Feng Xiangdi")




