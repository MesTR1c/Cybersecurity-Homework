# Report

在本项目中一共复刻了关于SM2的4种pitfall：

### leaking k

![](pics/原理1.png)

### reusing k

![](pics/原理2.png)

### reusing k by different users

![](pics/原理3.png)

### same d and k with ECDSA

![](pics/原理4.png)

在代码中我复现了这些pitfalls，最终结果如下所示：

![](pics/结果.png)