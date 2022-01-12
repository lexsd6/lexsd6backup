
title:  \`could not patch the PLT stub; unexpected PLT format or the file has been modified after linking!\`报错缓解方法
categories: [tools]
tags: [ida,problem_resolve]

---

额,之前一直被`could not patch the PLT stub; unexpected PLT format or the file has been modified after linking!`这个报错恶心了很久,今天无意间终于找到了解决(补救方案)。<!--more-->

## 报错状况描述

在报错后，出现 `.plt.sec` 的segement。libc的symbols能被ida正常解析，但是并未被ida自动连接绑定上。本该解析libc symbols的地方，显示的是`.plt.sec`的值， 如图：

![image-20210916112022149](image-20210916112022149.png)

## 解决方法

添加插件：pltresolver

项目地址：https://github.com/veritas501/pltresolver

在ida项目中的`plugins`倒入脚本：

![image-20210916113633798](image-20210916113633798.png)

打开ida看到`pltResolver plugin has been loaded.
Press Ctrl+Shift+J to resolve .plt.sec symbols.`即为倒入成功！

![image-20210916113730185](image-20210916113730185.png)

## 修复后效果

看到ida 把libc sysmbols用重新识别上了： 

![image-20210916113420325](image-20210916113420325.png)