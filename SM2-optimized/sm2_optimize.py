import binascii
from distutils.cmd import Command
from random import choice
import random
import time
from tkinter import GROOVE, font
import sm3, func
import tkinter as tk
import screeninfo
from tkinter import ttk
from tkinter import Button
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
    def sign(self, data, K):  # 签名函数, data消息的hash，private_key私钥，K随机数，均为16进制字符串
        E = data.hex() # 消息转化为16进制字符串
        e = int(E, 16)

        d = int(self.private_key, 16)
        k = int(K, 16)

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
    def encrypt(self, data):
        # 加密函数，data消息(bytes)
        msg = data.hex() # 消息转化为16进制字符串
        k = func.random_hex(self.para_len)
        C1 = self._kg2(int(k,16),self.ecc_table['g'])
        xy = self._kp2(int(k,16),self.public_key)
        '''C11 = self._kg(int(k,16),self.public_key)
        print(xy)
        print(C11)'''
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:2*self.para_len]
        ml = len(msg)
        t = sm3.sm3_kdf(xy.encode('utf8'), ml/2)
        if int(t,16)==0:
            return None
        else:
            form = '%%0%dx' % ml
            C2 = form % (int(msg, 16) ^ int(t, 16))
            C3 = sm3.sm3_hash([
                i for i in bytes.fromhex('%s%s%s'% (x2,msg,y2))
            ])
            return bytes.fromhex('%s%s%s' % (C1,C3,C2))
    def decrypt(self, data):
        # 解密函数，data密文（bytes）
        data = data.hex()
        len_2 = 2 * self.para_len
        len_3 = len_2 + 64
        C1 = data[0:len_2]
        C3 = data[len_2:len_3]
        C2 = data[len_3:]
        xy = self._kp(int(self.private_key,16),C1,C1)
        # print('xy = %s' % xy)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:len_2]
        cl = len(C2)
        t = sm3.sm3_kdf(xy.encode('utf8'), cl/2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % cl
            M = form % (int(C2,16) ^ int(t,16))
            u = sm3.sm3_hash([
                i for i in bytes.fromhex('%s%s%s'% (x2,M,y2))
            ])
            return bytes.fromhex(M)
    def verify_original(self, Sign, data):
        # 验签函数，sign签名r||s，E消息hash，public_key公钥
        r = int(Sign[0:self.para_len], 16)
        s = int(Sign[self.para_len:2*self.para_len], 16)
        e = int(data.hex(), 16)
        t = (r + s) % int(self.ecc_table['n'], base=16)
        if t == 0:
            return 0

        P1 = self._kg(s, self.ecc_table['g'])
        P2 = self._kg(t, self.public_key)
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
    def sign_original(self, data, K):  # 签名函数, data消息的hash，private_key私钥，K随机数，均为16进制字符串
        E = data.hex() # 消息转化为16进制字符串
        e = int(E, 16)

        d = int(self.private_key, 16)
        k = int(K, 16)

        P1 = self._kg(k, self.ecc_table['g'])

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
    def encrypt_original(self, data):
        # 加密函数，data消息(bytes)
        msg = data.hex() # 消息转化为16进制字符串
        k = func.random_hex(self.para_len)
        C1 = self._kg(int(k,16),self.ecc_table['g'])
        xy = self._kg(int(k,16),self.public_key)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:2*self.para_len]
        ml = len(msg)
        t = sm3.sm3_kdf(xy.encode('utf8'), ml/2)
        if int(t,16)==0:
            return None
        else:
            form = '%%0%dx' % ml
            C2 = form % (int(msg, 16) ^ int(t, 16))
            C3 = sm3.sm3_hash([
                i for i in bytes.fromhex('%s%s%s'% (x2,msg,y2))
            ])
            return bytes.fromhex('%s%s%s' % (C1,C3,C2))
    def decrypt_original(self, data):
        # 解密函数，data密文（bytes）
        data = data.hex()
        len_2 = 2 * self.para_len
        len_3 = len_2 + 64
        C1 = data[0:len_2]
        C3 = data[len_2:len_3]
        C2 = data[len_3:]
        print(self.private_key)
        xy = self._kg(int(self.private_key,16),C1)
        # print('xy = %s' % xy)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:len_2]
        cl = len(C2)
        t = sm3.sm3_kdf(xy.encode('utf8'), cl/2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % cl
            M = form % (int(C2,16) ^ int(t,16))
            u = sm3.sm3_hash([
                i for i in bytes.fromhex('%s%s%s'% (x2,M,y2))
            ])
            return bytes.fromhex(M)
    def verify_new(self, Sign, data):
        # 验签函数，sign签名r||s，E消息hash，public_key公钥
        r = int(Sign[0:self.para_len], 16)
        s = int(Sign[self.para_len:2*self.para_len], 16)
        e = int(data.hex(), 16)
        t = (r + s) % int(self.ecc_table['n'], base=16)
        if t == 0:
            return 0

        P1 = self._kg2_2(s, self.ecc_table['g'])
        P2 = self._kp2_2(t, self.public_key)
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
    def sign_new(self, data, K):  # 签名函数, data消息的hash，private_key私钥，K随机数，均为16进制字符串
        E = data.hex() # 消息转化为16进制字符串
        e = int(E, 16)

        d = int(self.private_key, 16)
        k = int(K, 16)

        P1 = self._kg2_2(k, self.ecc_table['g'])

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
    def encrypt_new(self, data):
        # 加密函数，data消息(bytes)
        msg = data.hex() # 消息转化为16进制字符串
        k = func.random_hex(self.para_len)
        C1 = self._kg2_2(int(k,16),self.ecc_table['g'])
        xy = self._kp2_2(int(k,16),self.public_key)
        '''C11 = self._kg(int(k,16),self.public_key)
        print(xy)
        print(C11)'''
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:2*self.para_len]
        ml = len(msg)
        t = sm3.sm3_kdf(xy.encode('utf8'), ml/2)
        if int(t,16)==0:
            return None
        else:
            form = '%%0%dx' % ml
            C2 = form % (int(msg, 16) ^ int(t, 16))
            C3 = sm3.sm3_hash([
                i for i in bytes.fromhex('%s%s%s'% (x2,msg,y2))
            ])
            return bytes.fromhex('%s%s%s' % (C1,C3,C2))
    def decrypt_new(self, data):
        # 解密函数，data密文（bytes）
        data = data.hex()
        len_2 = 2 * self.para_len
        len_3 = len_2 + 64
        C1 = data[0:len_2]
        C3 = data[len_2:len_3]
        C2 = data[len_3:]
        xy = self._kp_2(int(self.private_key,16),C1,C1)
        # print('xy = %s' % xy)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:len_2]
        cl = len(C2)
        t = sm3.sm3_kdf(xy.encode('utf8'), cl/2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % cl
            M = form % (int(C2,16) ^ int(t,16))
            u = sm3.sm3_hash([
                i for i in bytes.fromhex('%s%s%s'% (x2,M,y2))
            ])
            return bytes.fromhex(M)
private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

sm2_crypt = CryptSM2(
    public_key=public_key, private_key=private_key)
#数据和加密后数据为bytes类型




class package():
  def get_monitor_screen(self,x, y):
    monitors = screeninfo.get_monitors()
    for m in reversed(monitors):
        if m.x <= x <= m.width + m.x and m.y <= y <= m.height + m.y:
            return m
    return monitors[0]
  def window(self):
    window=tk.Tk()
    window.title("test")
    current_screen = self.get_monitor_screen(window.winfo_x(), window.winfo_y())
    # 设置app的宽和高
    appWidth = 500
    appHeigh = 500
    # 获取当前屏幕的宽高
    screenWidth = current_screen.width
    screenHeigh = current_screen.height
    x = (screenWidth - appWidth) / 2
    y = (screenHeigh - appHeigh) / 2
    window.geometry("%dx%d+%d+%d"% (appWidth, appHeigh, x, y))
    s = ttk.Style()
    s.configure('TNotebook.Tab', font=('微软雅黑','15') )
    notebook = ttk.Notebook(window)
    frame_1, frame_2,frame_3 = [tk.Frame(notebook, bg='white', width=500, height=500) for i in range(3)]
    notebook.add(frame_1, text='说明')
    notebook.add(frame_2, text='正确性验证')
    notebook.add(frame_3, text='计算kP的效率')
    notebook.grid(row=0, column=0, sticky="nw")

    ###frame1布置
    text = tk.Text(frame_1)
    text.configure(font='微软雅黑 13',width=42,height=19,relief=GROOVE)
    text.pack(side='top')
    # "insert" 索引表示插入光标当前的位置
    text.insert('insert',"  在这个可执行程序中，将分别演示：扩展双基链树形方法和基于扩展双基链树形方法的随即系数选择方法的正确性、GmSSL库中原本的算法效率同上述两种算法的效率比较。\n  在这个测试程序中使用的公钥和私钥（16进制）分别为\n private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'\n public_key ='B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'\n  椭圆曲线参数分别为:\n 'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',\n 'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',\n 'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',\n 'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',\n 'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'")
    text.configure(state='disabled')
    
      
    ###frame2布置
    frame_21, frame_22, frame_23 = [tk.Frame(frame_2) for i in range(3)]
    frame_21.pack()
    frame_22.pack()
    frame_23.pack()
    
    label1=tk.Label(frame_21,text="请输入您想要加密的字符到下方的输入框中,并点击输入按钮",font='微软雅黑 12')
    label1.pack(padx=10, pady=5, side='left', anchor='nw',fill="both")

    shuru=""
    entry2=tk.Entry(frame_22)
    entry2.pack(padx=10, pady=5, side='left', anchor='nw')
    entry31=tk.Entry(frame_23)
    entry35=tk.Entry(frame_23)
    entry40=tk.Entry(frame_23)
    def clicked1(x):
      entry31.delete(0,"end")
      entry35.delete(0,"end")
      entry40.delete(0,"end")
      x=entry2.get()
      entry2.delete(0,"end")
      label30=tk.Label(frame_23,text="您的输入是:",font='微软雅黑 12')
      label30.grid(column=0,row=0)
      entry31.insert(0,x)
      entry31.grid(column=1,row=0)
      label32=tk.Label(frame_23,text="用扩展双基链的树形方法加密过后为(bytes形式):",font='微软雅黑 12')
      label32.grid(column=0,row=1)
      text33 = tk.Text(frame_23)
      text33.configure(font='微软雅黑 12',width=42,height=3,relief=GROOVE)
      text33.grid(column=0,row=2)
      a=sm2_crypt.encrypt(x.encode())
      text33.insert('insert',str(a))
      text33.configure(state='disabled')
      label34=tk.Label(frame_23,text="用扩展双基链的树形方法解密过后为:",font='微软雅黑 12')
      label34.grid(column=0,row=3)
      y=sm2_crypt.decrypt(a)
      entry35.insert(0,str(y.decode()))
      entry35.grid(column=1,row=3)

      label36=tk.Label(frame_23,text="用随机策略选择算法加密过后为(bytes形式):",font='微软雅黑 12')
      label36.grid(column=0,row=4)
      text37 = tk.Text(frame_23)
      text37.configure(font='微软雅黑 12',width=42,height=3,relief=GROOVE)
      text37.grid(column=0,row=5)
      a=sm2_crypt.encrypt_new(x.encode())
      text37.insert('insert',str(a))
      text37.configure(state='disabled')
      label39=tk.Label(frame_23,text="用随机策略选择算法解密过后为:",font='微软雅黑 12')
      label39.grid(column=0,row=6)
      y=sm2_crypt.decrypt_new(a)
      entry40.insert(0,str(y.decode()))
      entry40.grid(column=1,row=6)
      label41=tk.Label(frame_23,text="",font='微软雅黑 12') #占位
      label41.grid(column=0,row=7)
      text42 = tk.Text(frame_23)
      text42.configure(font='微软雅黑 12',width=42,height=2,relief=GROOVE)
      text42.grid(column=0,row=8)
      text42.insert('insert',"注：因为设计的算法中每次加密计算kP时使用的k是随机的，因此加密的结果也是随机的。")
      text42.configure(state='disabled')
    Button(frame_22, text="输入",command=lambda:clicked1(shuru)).pack(padx=10, pady=5, side='left', anchor='nw')

    ###frame 3 布置：
    frame_31, frame_32, frame_33 = [tk.Frame(frame_3) for i in range(3)]
    frame_31.pack()
    frame_32.pack()
    frame_33.pack()
    label330=tk.Label(frame_31,text="如果您想随机输入一个256bit的整数，您可以点击随机按钮",font='微软雅黑 12')
    label330.pack(padx=10, pady=5, side='top', anchor='nw',fill="both")
    label331=tk.Label(frame_31,text="您也可以自己输入整数，但为了保证测试效果，请输入256bit左右整数，并点击输入",font='微软雅黑 10')
    label331.pack(padx=10, pady=5, side='top', anchor='nw',fill="both")
    entry3=tk.Entry(frame_32)
    entry3.pack(padx=10, pady=5, side='left', anchor='nw')

    shuru1=""
    def clicked2(x):
      x=entry3.get()
      entry3.delete(0,"end")
      label332=tk.Label(frame_33,text="待计算的k是:",font='微软雅黑 12')
      label332.grid(column=0,row=0)
      text333 = tk.Text(frame_33)
      text333.configure(font='微软雅黑 12',width=30,height=2,relief=GROOVE)
      text333.grid(column=1,row=0)
      text333.insert('insert',x)
      text333.configure(state='disabled')

      label334=tk.Label(frame_33,text="用GmSSL库中方法计算100次耗时：",font='微软雅黑 12')
      label334.grid(column=0,row=1)
      time1=0
      for i in range(100):
          start = time.time()
          sm2_crypt._kg(int(x),sm2_crypt.ecc_table['g'])
          end =time.time()
          time1=time1+end-start
      text335 = tk.Text(frame_33)
      text335.configure(font='微软雅黑 12',width=30,height=1,relief=GROOVE)
      text335.grid(column=1,row=1)
      text335.insert('insert',str(time1))
      text335.insert('insert'," s")
      text335.configure(state='disabled')

      label336=tk.Label(frame_33,text="用扩展双基链的树形方法耗时：",font='微软雅黑 12')
      label336.grid(column=0,row=2)
      time1=0
      for i in range(100):
          start = time.time()
          sm2_crypt._kg2(int(x),sm2_crypt.ecc_table['g'])
          end =time.time()
          time1=time1+end-start
      text337 = tk.Text(frame_33)
      text337.configure(font='微软雅黑 12',width=30,height=1,relief=GROOVE)
      text337.grid(column=1,row=2)
      text337.insert('insert',str(time1))
      text337.insert('insert'," s")
      text337.configure(state='disabled')
      
      label338=tk.Label(frame_33,text="用随即系数策略选择算法耗时：",font='微软雅黑 12')
      label338.grid(column=0,row=3)
      time1=0
      for i in range(100):
          start = time.time()
          sm2_crypt._kg2_2(int(x),sm2_crypt.ecc_table['g'])
          end =time.time()
          time1=time1+end-start
      text339 = tk.Text(frame_33)
      text339.configure(font='微软雅黑 12',width=30,height=1,relief=GROOVE)
      text339.grid(column=1,row=3)
      text339.insert('insert',str(time1))
      text339.insert('insert'," s")
      text339.configure(state='disabled')


    def clicked3():
      y=func.random_hex(64)
      label332=tk.Label(frame_33,text="待计算的k是:",font='微软雅黑 12')
      label332.grid(column=0,row=0)
      text333 = tk.Text(frame_33)
      text333.configure(font='微软雅黑 12',width=30,height=2,relief=GROOVE)
      text333.grid(column=1,row=0)
      x=int(y,16)
      text333.insert('insert',str(x))
      text333.configure(state='disabled')

      label334=tk.Label(frame_33,text="用GmSSL库中方法计算100次耗时：",font='微软雅黑 12')
      label334.grid(column=0,row=1)
      time1=0
      for i in range(100):
          start = time.time()
          sm2_crypt._kg(x,sm2_crypt.ecc_table['g'])
          end =time.time()
          time1=time1+end-start
      text335 = tk.Text(frame_33)
      text335.configure(font='微软雅黑 12',width=30,height=1,relief=GROOVE)
      text335.grid(column=1,row=1)
      text335.insert('insert',str(time1))
      text335.insert('insert'," s")
      text335.configure(state='disabled')

      label336=tk.Label(frame_33,text="用扩展双基链的树形方法100次耗时：",font='微软雅黑 12')
      label336.grid(column=0,row=2)
      time1=0
      for i in range(100):
          start = time.time()
          sm2_crypt._kg2(x,sm2_crypt.ecc_table['g'])
          end =time.time()
          time1=time1+end-start
      text337 = tk.Text(frame_33)
      text337.configure(font='微软雅黑 12',width=30,height=1,relief=GROOVE)
      text337.grid(column=1,row=2)
      text337.insert('insert',str(time1))
      text337.insert('insert'," s")
      text337.configure(state='disabled')
      
      label338=tk.Label(frame_33,text="用随即系数策略选择算法100次耗时：",font='微软雅黑 12')
      label338.grid(column=0,row=3)
      time1=0
      for i in range(100):
          start = time.time()
          sm2_crypt._kg2_2(x,sm2_crypt.ecc_table['g'])
          end =time.time()
          time1=time1+end-start
      text339 = tk.Text(frame_33)
      text339.configure(font='微软雅黑 12',width=30,height=1,relief=GROOVE)
      text339.grid(column=1,row=3)
      text339.insert('insert',str(time1))
      text339.insert('insert'," s")
      text339.configure(state='disabled')
    Button(frame_32, text="随机",command=lambda:clicked3()).pack(padx=10, pady=5, side='left', anchor='nw')
    Button(frame_32, text="输入",command=lambda:clicked2(shuru1)).pack(padx=10, pady=5, side='left', anchor='nw')
    

    window.mainloop()
package1=package()
package1.window()







'''
data1="测试"
data = data1.encode()

enc_data = sm2_crypt.encrypt_new(data)
dec_data =sm2_crypt.decrypt_new(enc_data)
print('enc_data:',type(str(enc_data)))
print('dec_data:',dec_data.decode())
assert dec_data == data
data = b"111" # bytes类型
random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign_new(data, random_hex_str) #  16进制
print('signed message:',sign)
assert sm2_crypt.verify_new(sign, data) #  16进制
'''