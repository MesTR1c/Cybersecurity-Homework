# 1.个人信息：

* 姓名：冯相迪
* 学号：201900460020
* 年级：19级
* 本仓库系个人完成
* github 账户：MesTR1c

# 2.备注：

* 注：homework 1-4 系在实验课上研读或作修改的产物，与项目内容无关，老师可以直接跳过阅读其余内容，具体项目都在每个文件夹中
* 注：因为是个人完成，所以项目完成人都是我自己，所以无项目贡献度排序
* 注：对于每个项目，都有以下几样内容组成：
  * 1.pics文件，存储了report.md中所需要的图片信息
  * 2.report.pdf，report.md的pdf版本
  * 3.report.md，包括了项目原理、对于如何实现的分析、执行步骤、执行过程截图、运行结果截图等内容。
    * 有时report.md中会出现图片加载失败的情况，您可以查看pdf版本或直接去对应目录的pics查看
  * 4.重要函数及运行说明.md，里面包含了对于一些典型函数的作用说明，以及如何执行代码等内容，对于一些有依赖项的代码来说（如很多的sm2代码），我将代码和依赖项都放在同一个目录中，可能会有些混乱，因此这个文件记录了主要代码在哪个文件中，以及在网络通信中执行代码文件的顺序等。
  * 5.主要代码及其依赖项

# 3.项目列表：

### 已完成项目（共计15个）：

### reduced-SM3-birthday attack

* 项目简介：缩减的SM3生日攻击，寻找碰撞

### reduced-SM3-rho method

* 项目简介：缩减的SM3 中使用rho method寻找碰撞

### SM3-length extension attack

* 项目简介：sm3的长度扩展攻击

### merkle tree

* 项目简介：构建一颗10w叶子的merkle tree 并且给出存在性和非存在性证明

### ECDSA-deduce publickey

* 项目简介：在不传输公钥的情况下，通过多传输2bit信息，确定性地恢复ECDSA的公钥

### ECDSA-forge sig

* 项目简介：在ECDSA算法下，任意构造一个签名，证明我是某个人（中本聪）

### SM2-ECMH

* 项目简介：完成了基于SM2的ECMH策略

### SM2-PGP

* 项目简介：完成了基于SM2的PGP策略

### SM2-Poc-Scheme

* 项目简介：完成了一个基于SM2的朴素的Poc策略

### SM2-RFC6979-deterministic-generate-k

* 项目简介：根据RFC6979的标准，确定性地生成随机数k

### SM2-pitfall

* 项目简介：实现了4个关于sm2签名的pitfalls

### SM2-two-party decrypt

* 项目简介：在真实网络通信下，实现了一个基于SM2的2P decrypt

### SM2-two-party sign

* 项目简介：在真实网络通信下，实现了一个基于SM2的2P sign

### bitcoin parse tx

* 项目简介：编写脚本，给Bitcoin testnet发送一个tx，分析tx_data的信息

### SM2-optimized

* 项目简介：优化SM2中的椭圆曲线点乘，采用扩展双基链的树形方法和随机策略选取方法来提升效率和安全性





### 未完成的项目：

* 优化SM3（软件层面）
* 优化SM4（SIMD）
* Find a key with hash value “sdu-cst-20220610”，with message your student ID + your name
* 寻找hash值对称的64字节数据
* 证明你的6级成绩高于425 via circuit
