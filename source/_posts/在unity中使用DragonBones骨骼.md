title: 在unity中使用DragonBones骨骼的方法
categories: [unity]
tags: [DragonBones,c#]
---
最近跑路的事情稳了，又拿出2019年设计的小游戏草案在那里改。找文章发现DragonBones骨骼可以用来unity中使用。但项目需求使用时，踩了很多坑。<!--more-->

## 导入插件

在github(https://github.com/DragonBones/DragonBonesCSharp) 下载插件.

然后：

1. 创建一个 Unity 项目或使用上述示例项目。
2. 分别复制 [DragonBones 公共库源码](https://github.com/DragonBones/DragonBonesCSharp/blob/master/DragonBones/src)、[DragonBones Unity 库源码](https://github.com/DragonBones/DragonBonesCSharp/blob/master/Unity/src)、[第三方库源码](https://github.com/DragonBones/DragonBonesCSharp/blob/master/3rdParty) 中的所有文件夹和文件到项目的 Assets/Scripts 文件夹下。
3. 运行项目。

确保项目结构如下:

```
Your project
    |-- Assets
        |-- DragonBones
            |-- Demos (如果不需要，可以删除。)
            |-- Scripts        
                |-- 3rdParty
                |-- animation
                |-- armature
                |-- ...
                |-- unity
                |-- ...
            |-- Editor
            |-- Resources
                |-- Shaders files
                |-- ...
            |-- ...
        |-- Resources
            |-- DragonBonesData files
            |-- ...
        |-- Scripts
        |-- ...
    |-- ...
```-- ...
```



## 素材导入

### 图像界面导入

unity图像界面导入DragonBones骨骼比较简单。分为Data数据导入和直接法。

#### 直接导入

在插件导入后，我们就点击右键ske文件，点击DragonBones中`Armature Object`,可以生成DragonBones骨骼动画对象。

![image-20220520110016570](image-20220520110016570.png)

#### Data数据

在插件导入后，我们就点击右键ske文件，点击DragonBones中`Create Unity Data`,可以生成data文件。

![image-20220520101926214](image-20220520101926214.png)

在把文件拖入DragonBones对象里。

![image-20220520105643528](image-20220520105643528.png)

### 代码导入

参照官方demo教程--`HelloDragonBones.cs`改动的，纯代码导入

```c#
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using DragonBones;
public class testal : MonoBehaviour//BaseDemo //MonoBehaviour
{  
    private UnityDragonBonesData dragonBoneData;
    // Update is called once per frame
    // Start is called before the first frame update
    // protected override void OnStart()
    void Start()
    {
        dragonBoneData=UnityEditor.AssetDatabase.LoadAssetAtPath<UnityDragonBonesData>("Assets/ylw/xlw_Data.asset");
        // 1.Load and parse data
       // Debug.Log(dragonBoneData.dragonBonesJSON);
        if (true)
        {
            // Scheme 1: Load UnityDragonBonesData
            UnityFactory.factory.LoadData(this.dragonBoneData);
        }
        else
        {
            // Scheme 2: Load JsonData in Resources
             //UnityFactory.factory.LoadDragonBonesData("/Assets/ylw/xlw_ske.json");
             //UnityFactory.factory.LoadTextureAtlasData("/Assets/ylw/xlw_tex.json");
        }

        // 2.Build armature
        var armatureComponent = UnityFactory.factory.BuildArmatureComponent("animx");

        // 3.Play animation
        armatureComponent.animation.Play("stand");
       
        // Set name
        armatureComponent.name = "dynamic_mecha_1002_101d";

        // Set position.

        armatureComponent.transform.localPosition = new Vector3(3.0f, -1.5f, 1.0f);
    }

    // Update is called once per frame
    void Update()
    {

    }
}
```

在这里要注意的是`UnityFactory.factory.BuildArmatureComponent()`函数的参数与ske文件中的`armature`属性里的`name`的值相关，两者要一致。

同时，如果是**高版本素材**推荐用**scheme1**导入，**低版本**用**scheme2**。否则，代码导入后有蜜汁bug。

另外代码导入时，确保正确生成了mat文件，否则也有蜜汁bug。官方代码里先读取文件再判断是否生成orw。。。。





## 用代码获得骨骼动画对象

我们在导入unity后,我们可以通过UnityArmatureComponent控件来管理我们DragonBones骨骼动画。

我们可以GETcomponent来获取我们的DragonBones骨骼动画对象：

```c#
public DragonBones.UnityArmatureComponent anmi;
anmi=xxx.GetComponent<DragonBones.UnityArmatureComponent>();
```

也可以直接使用拖拽法

![image-20220517113029077](image-20220517113029077.png)

## 用代码控制骨骼动画播放

官方提供的获得控制骨骼动画播放与播放状态属性的API，这些与播放相关的API多数放在animation属性下。

具体API简略整理如下：

### 通过指定的动画配置来播放动画

```c#
 public AnimationState PlayConfig(AnimationConfig animationConfig)
```

 通过指定的动画配置来播放动画。 该 API 仍在实验阶段，使用时可能遭遇 bug 或稳定性或兼容性问题。

参数：

`animationConfig`：是指动画配置。

### 播放指定动画

```c#
public AnimationState Play(string animationName = null, int playTimes = -1)
```

播放指定动画，并设置循环次数。

参数:

`animationName `:运行动画名称。

`playTimes`:循环次数  [-1: 使用动画数据默认值, 0: 无限循环播放, [1~N]: 循环播放 N 次] （默认: -1）示例：

```c#
 armature.animation.play("walk");
```

### 淡入播放指定的动画

```c#
  public AnimationState FadeIn(string animationName, float fadeInTime = -1.0f, int playTimes = -1,
                                    int layer = 0, string group = null,
                                    AnimationFadeOutMode fadeOutMode = AnimationFadeOutMode.SameLayerAndGroup)
```

`FadeIn()`淡入播放指定的动画。

参数：

`animationName`：动画数据名称。

 `fadeInTime `:淡入时间。 [-1: 使用动画数据默认值, [0~N]: 淡入时间 (以秒为单位)] （默认: -1）

`playTimes`: 播放次数。 [-1: 使用动画数据默认值, 0: 无限循环播放, [1~N]: 循环播放 N 次] （默认: -1）

`layer`:混合图层，图层高的动画状态会优先获取混合权重，当混合权重分配总和超过 1.0 时，剩余的动画状态将不能再获得权重分配。 （默认: 0）

`group` 混合组名称，该属性通常用来指定多个动画状态混合时的相互替换关系。 （默认: null）

`fadeOutMode`:淡出模式，该属性通常用来指定多个动画状态混合时的相互替换模式。 （默认: `AnimationFadeOutMode.SameLayerAndGroup`）

返回值：

播放的状态。

PS:淡出模式的具体模式有:

```c#
AnimationFadeOutMode.None //不淡出任何的动画状态，值同等于0   
    
AnimationFadeOutMode.SameLayer //淡出同层的动画状态，值同等于1
    
AnimationFadeOutMode.SameGroup// 淡出同组的动画状态，值同等于2

AnimationFadeOutMode.SameLayerAndGroup //淡出同层并且同组的动画状态，值同等于3

AnimationFadeOutMode.ALL//淡出所有的动画状态，值同等于4

AnimationFadeOutMode.Single // 不替换同名的动画状态，值同等于5

```

示例：

```c#
armature.animation.fadeIn("walk", 0.3, 0, 0, "normalGroup").resetToPose = false;
armature.animation.fadeIn("attack", 0.3, 1, 0, "attackGroup").resetToPose = false;
```



### 指定时间开始播放指定动画

```c#
public AnimationState GotoAndPlayByTime(string animationName, float time = 0.0f, int playTimes = -1)
```

`GotoAndPlayByTime()`-指定时间开始播放.

参数：

`animationName`- 动画数据名称。

  `time`- 播放开始的时间。 (以秒为单位)

`playTimes`- 循环播放次数。 [-1: 使用动画数据默认值, 0: 无限循环播放, [1~N]: 循环播放 N 次] （默认: -1）

返回值：

播放的动画状态。

### 指定帧开始播放指定动画

```c#
public AnimationState GotoAndPlayByFrame(string animationName, uint frame = 0, int playTimes = -1)
```

`GotoAndPlayByFrame`从指定帧开始播放指定的动画

参数:

`animationName`- 动画数据名称。

`frame`- 播放开始的帧数。

`playTimes`- 播放次数。 [-1: 使用动画数据默认值, 0: 无限循环播放, [1~N]: 循环播放 N 次] （默认: -1）

返回值：

播放的动画状态。

### 指定进度开始播放指定的动画

```c#
public AnimationState GotoAndPlayByProgress(string animationName, float progress = 0.0f, int playTimes = -1)
```

`GotoAndPlayByProgress`指定进度开始播放指定的动画。

参数：

`animationName` 动画数据名称。

`progress`- 开始播放的进度。

`playTimes`- 播放次数。 [-1: 使用动画数据默认值, 0: 无限循环播放, [1~N]: 循环播放 N 次] （默认: -1）

返回值：

returns-播放的动画状态。

### 指定时间停止指定动画播放

```c#
public AnimationState GotoAndStopByTime(string animationName, float time = 0.0f)
```

在指定时间停止指定动画播放。

参数：

`animationName`- 动画数据名称。

`time`- 停止的时间。 (以秒为单位)

返回值：播放的动画状态。

### 指定帧停止指定动画的播放

```c#
 public AnimationState GotoAndStopByFrame(string animationName, uint frame = 0)
```

在指定帧停止指定动画的播放

参数：

`animationName`- 动画数据名称.

`frame`- 停止的帧数。

 返回值：

播放的动画状态。

### 指定的进度停止指定的动画播放

```c#
 public AnimationState GotoAndStopByProgress(string animationName, float progress = 0.0f)
```

指定的进度停止指定的动画播放

参数：

`animationName`- 动画数据名称。

`progress`- 停止进度。

返回状态：播放的动画状态。

### 获取指定的动画状态

```c#
public AnimationState GetState(string animationName)
```

获取指定的动画状态

参数：

`animationName`- 动画状态名称。

示例：

```c#
armature.animation.play("walk");
et walkState = armature.animation.getState("walk");
walkState.timeScale = 0.5;
```

### 检查是否包含指定的动画数据

```c#
public bool HasAnimation(string animationName)
        {
            return this._animations.ContainsKey(animationName);
        }
```

`HasAnimation()`检查是否包含指定的动画数据

参数：

`animationName`- 动画数据名称。

###  获取所有的动画状态

```c#
public List<AnimationState> GetStates()
```

`GetStates()` 获取所有的动画状态.

### 检查是否有动画状态正在播放

```c#
public bool isPlaying
```

示例：

```c#
armature.animation.isPlaying
```

为True  表在播放，为flase则未在播放。

### 检查是否所有的动画状态均已播放完毕

```c#
public bool isCompleted
```

示例：

```c#
armature.animation.isCompleted
```

### 上一个播放的动画状态名称

```c#
public string lastAnimationName
// 示例：
armature.animation.isCompleted
```

### 所有动画数据的名称

```c#
public List<string> animationNames
```

### 所有的动画数据

```c#
  public Dictionary<string, AnimationData> animations
```

一个可以快速使用的动画配置实例

```c#
public AnimationConfig animationConfig
```

### 上一个播放的动画状态

```c#
public AnimationState lastAnimationState
```

## 替换骨骼动画

Assets\DragonBones\Editor\UnityEditor.cs  里用执行替换骨骼动画的函数--`ChangeDragonBonesData`

拷贝`Assets\DragonBones\Editor\UnityEditor.cs  `到目录`Assets\DragonBones\Scripts\animation\`

​    

```c#
public static bool ChangeDragonBonesData(UnityArmatureComponent _armatureComponent, TextAsset dragonBoneJSON)
```

`ChangeDragonBonesData`的一个参数时要替换骨骼与动画`UnityArmatureComponent`控件，二个是替换成的dragonBoneJSON数据。

示例：

```c#

var anmi2=xxx.GetComponent<DragonBones.UnityArmatureComponent>();
UnityDragonBonesData SSS;
UnityFactory.factory.Clear(true); //清楚缓存
SSS=UnityEditor.AssetDatabase.LoadAssetAtPath<UnityDragonBonesData>("Assets/kwww/ssss_Data.asset");
DragonBones.UnityEditor.ChangeDragonBonesData(anmi2,SSS.dragonBonesJSON); 
```



## 参考文献

https://github.com/DragonBones/DragonBonesCSharp

https://github.com/DragonBones/DragonBonesCSharp/blob/master/README-zh_CN.md

https://github.com/DragonBones/DragonBonesCSharp/blob/master/Unity/README-zh_CN.md







```c#

```





