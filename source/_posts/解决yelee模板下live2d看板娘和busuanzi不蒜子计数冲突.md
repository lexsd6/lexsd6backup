
title:  解决yelee模板下live2d看板娘和busuanzi不蒜子计数冲突
categories: [Yelee]
tags: [problem_resolve,node-js]

---
今天强迫症又双发作，这次没忍住，折腾了下。重于把hexo-helper-live2d 与busuanzi 两个插件共存时产生冲突的问题解决了。<!--more-->

## 问题描述

未安装live2d且不蒜子配置正常，执行`npm install --save hexo-helper-live2d`后，不蒜子计数冲突不显示计数。
已安装live2d但`live2d.enable`由`true`改为`false`后，不蒜子显示计数。

同时正常时，代码为：

```html
<span id="busuanzi_container_site_pv">
    |&nbsp;<i class="far fa-eye"></i>&nbsp;总访问量:&nbsp;<span id="busuanzi_value_site_pv"
        class="white-color"></span>&nbsp;次
    </span>
<span id="busuanzi_container_site_uv">
    |&nbsp;<i class="fas fa-users"></i>&nbsp;总访问人数:&nbsp;<span id="busuanzi_value_site_uv"
        class="white-color"></span>&nbsp;人
    </span>
```

异常时，代码为：

```html

<span id="busuanzi_container_site_pv" style="display: none;">
    |&nbsp;<i class="far fa-eye"></i>&nbsp;总访问量:&nbsp;<span id="busuanzi_value_site_pv"
        class="white-color"></span>&nbsp;次
    </span>
<span id="busuanzi_container_site_uv" style="display: none;">
    |&nbsp;<i class="fas fa-users"></i>&nbsp;总访问人数:&nbsp;<span id="busuanzi_value_site_uv"
        class="white-color"></span>&nbsp;人
    </span>
```

## 解决方案

1.打开footer.ejs文件，找到与不蒜子相关的代码：

```ejs
        <% if (theme.visit_counter.on) { %>
            <div class="visit">
                <% if (theme.visit_counter.site_visit) { %>
                    <span id="busuanzi_container_site_pv" style='display:inline'>
                        <span id="site-visit" title="<%= __('visit_counter.site') %>"><i class="fa fa-user" aria-hidden="true"></i><span id="busuanzi_value_site_uv"></span>
                        </span>
                    </span>
                <% } %>
                <% if (theme.visit_counter.site_visit && theme.visit_counter.page_visit) { %>
                    <span>| </span>
                <% } %>
                <% if (theme.visit_counter.page_visit) { %>
                    <span id="busuanzi_container_page_pv" style='display:inline'>
                        <span id="page-visit"  title="<%= __('visit_counter.page') %>"><i class="fa fa-eye animated infinite pulse" aria-hidden="true"></i><span id="busuanzi_value_page_pv"></span>
                        </span>
                    </span>
                <% } %>
            </div>
        <% } %>
```

2.删除` <span id="busuanzi_container_page_pv" style='display:inline'> `和` <span id="busuanzi_container_site_pv" style='display:inline'>`语句。

3.在` <% if (theme.visit_counter.on) { %>`语句后，添加`<script async src="https://busuanzi.ibruce.info/busuanzi/2.3/busuanzi.pure.mini.js">
</script>`。

```ejs
        <% if (theme.visit_counter.on) { %>
			<script async="" src="https://busuanzi.ibruce.info/busuanzi/2.3/busuanzi.pure.mini.js">
			</script>
            <div class="visit">
                <% if (theme.visit_counter.site_visit) { %>
                   
                        <span id="site-visit" title="<%= __('visit_counter.site') %>"><i class="fa fa-user" aria-hidden="true"></i><span id="busuanzi_value_site_uv"></span>
                        </span>
                    </span>
                <% } %>
                <% if (theme.visit_counter.site_visit && theme.visit_counter.page_visit) { %>
                    <span>| </span>
                <% } %>
                <% if (theme.visit_counter.page_visit) { %>
                   
                        <span id="page-visit"  title="<%= __('visit_counter.page') %>"><i class="fa fa-eye animated infinite pulse" aria-hidden="true"></i><span id="busuanzi_value_page_pv"></span>
                        </span>
                    </span>
                <% } %>
            </div>
        <% } %>
```

4.打开`after-footer.ejs`，删除`<script async src="https://busuanzi.ibruce.info/busuanzi/2.3/busuanzi.pure.mini.js"></script>`.



