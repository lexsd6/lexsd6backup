title:  cocos2d官方文档汉化--Writing a cocos2d application
categories: [cocos]
tags: [translate,python]
date: 2019-4-10 13:23:54
---


在开始使用一个新的库或框架是很困难的，尤其是在有大量参考文献要阅读的情况下。虽然会忽略掉一些细节，但这篇文章将用很简洁快速地介绍cocos2d。<!--more-->



## Hello, World

我们将从必要的“Hello, World”来开始介绍，这个例子将打开一个带有一些文字在上面的窗口并且在等待一段时间后会关闭这个窗口。



### 步骤

通过导入cocos库开始：

```python
import cocos
```

建立一个`Layer`（层）的子类，并定义在这里编写定义你的逻辑代码：

```python
class HelloWorld(cocos.layer.Layer):
```

我们可以在构造函数中通过`super()`来继承调用父类。从而总是在构造函数中调用`super()`来继承`Layer`.

```python
def __init__(self):
    super(HelloWorld, self).__init__()
```

为了设置展现文本，我们将通过` cocos.text.Label()`创建一个`Label`（标签）. `cocos.text.Label`的关键参数有font_name(自定义字体)、font_size(字体大小)、anchr_x(字体的x轴描点)、anchr_y(字体的y轴描点)：

```python
label = cocos.text.Label(
    'Hello, world',
    font_name='Times New Roman',
    font_size=32,
    anchor_x='center', anchor_y='center'
)
```

通过对`label.position`赋值让label在窗口的中心显现：

```python
label.position = 320, 240
```

由于`Label`是`CocosNode`的子类，Label能被添加在`CocosNode`作为子节点。所有的`CocosNode`对象能知道如何渲染、执行、转换他们。让我们为通过`add()`为`Layer`添加一个子节点。

```python
self.add(label)
```

之后为了定义`HelloWorld`类，我们需要初始化和创建一个窗口。我们在`Director`进行初始化。

```python
cocos.director.director.init()
```

之后我们创造一个`HelloWorld`类的实例

```python
hello_layer = HelloWorld()
```

再之后我们创建一个包含图层实例(hello_layer)的scene(场景)：

```python
main_scene = cocos.scene.Scene (hello_layer)
```

最后我们运行这个场景：

```python
cocos.director.director.run(main_scene)
```

最好三步操作也可以简化为：

```python
cocos.director.director.run(cocos.scene.Scene(HelloWorld()))
```

### 样例代码

```python
import cocos

class HelloWorld(cocos.layer.Layer):
    def __init__(self):
        #继承调用cocos.layer.Layer父类的构造方法，来创建一个图层
        super(HelloWorld, self).__init__()
        #设置展现文本
        label = cocos.text.Label(
            'Hello, world',
            font_name='Times New Roman',
            font_size=32,
            anchor_x='center', anchor_y='center')
        #设置label的位置
        label.position = 0, 240
        #将文本添加在图层中
        self.add(label)

def main():
    cocos.director.director.init()#实例化directir 进行初始化
    hello_layer = HelloWorld()#实例化HelloWorld class
    main_scene = cocos.scene.Scene (hello_layer)#让场景包含图层
    cocos.director.director.run(main_scene)#运行显示场景


if __name__ == '__main__':
    main()
```

## Hello Actions

这个例子和之前的例子1有点类似，不过不同之处在于它向我们展示了运动的世界。运动就像是命令，我们可以命令所有` CocosNode object`去执行一个动作，

### 步骤

比如想我们的例子，我们import package：

```python
import cocos
```

如果你想进行多个操作，你可以将命令空间导入：

```python
from cocos.actions import *
```

我们可以通过创建一个`ColorLayer`的子类来创建一个有色彩的图层，并且通过super函数来设置颜色。

```python
class HelloWorld(cocos.layer.ColorLayer):
    def __init__(self):
        # blueish color
        super( HelloWorld, self ).__init__( 64,64,224,255)
```

与之前的例子相同，我们创造一个标签：

```python
label = cocos.text.Label('Hello, World!',
    font_name='Times New Roman',
    font_size=32,
    anchor_x='center', anchor_y='center')

# set the label in the center of the screen
label.position = 320,240
self.add( label )
```

在例子中，我们也创造和添加一个sprite（精灵）作为子节点。在cocos2d 中，精灵是sprite 对象。

```python
sprite = cocos.sprite.Sprite('grossini.png')
```

接下来，我们把‘精灵’安放在屏幕的中间。sprite object 的默认位置是(0,0)

```python
sprite.position = 320,240
```

我们通过将scale属性设置为3。这将会使我们的图像放的3倍。(默认的倍率是1)

```python
sprite.scale = 3
```

我们可以通过设置z属性，来设置对象yue在图层z轴的位置，z值越在最前面显示。

```python
self.add( sprite, z=1 )
```

我们创建一个ScaleBy 动作，它会让对象在2s里按比例缩放。

```python
scale = ScaleBy(3, duration=2)
```

现在我们告诉标签将这么做：

​	将图像在2s里放大三倍。

​	然后再在2s里缩小三倍。

​	最后反复循环动作。

我们用‘+’号来链接两个动作。

```python
label.do( Repeat( scale + Reverse( scale) ) )
```

然后我们告诉sprie做相同的动作不过是先缩小后放大：

```
sprite.do( Repeat( Reverse(scale) + scale ) )
```

然后我们依然利用director初始化：

```python
cocos.director.director.init()
hello_layer = HelloWorld ()
```

然后我们利用`RotateBy` action 让窗口在10s内进行360旋转。 

```python
hello_layer.do( RotateBy(360, duration=10) )
```

最后，添加上我们的执行：

```python
# A scene that contains the layer hello_layer
main_scene = cocos.scene.Scene (hello_layer)

# And now, start the application, starting with main_scene
cocos.director.director.run (main_scene)
```



### 样例代码

```python
import cocos
from cocos.actions import *


class HelloWorld (cocos.layer.ColorLayer):
    def __init__(self):
        #设置彩色图层
        super(HelloWorld ,self).__init__(64,64,224,255)
		#设置文本label 
        label = cocos.text.Label('Hello, World!',
        font_name='Times New Roman',
        font_size=32,
        anchor_x='center', anchor_y='center')

        # set the label in the center of the screen
        label.position = 320,240
        self.add( label )
        
        #添加图片
        sprite = cocos.sprite.Sprite('1.png')
        #图片位置
        sprite.position = 320,240 
        #缩放，这里是原图的0.3倍，步骤里是原图3倍
        sprite.scale = 0.3
        #添加到图层高度为1（目前的顶层）
        self.add( sprite, z=1 )
        
        #添加缩放动画
        scale = ScaleBy(3, duration=2)
        label.do( Repeat( scale + Reverse( scale) ) )
        sprite.do( Repeat( Reverse(scale) + scale ) )


def main():
    #初始化
    cocos.director.director.init()
    #实例化图层
    hello_layer = HelloWorld ()
    #对图层添加旋转动画
    hello_layer.do( RotateBy(360, duration=10) )
    # A scene that contains the layer hello_layer
    main_scene = cocos.scene.Scene (hello_layer)

    # And now, start the application, starting with main_scene
    cocos.director.director.run (main_scene)




if __name__ == '__main__':
    main()
```



## Handling Events

在我们之前的所有例子都是没有交互的。它们都只是展示了一些东西，但是没有对用户的输入进行回响（除了当我们按下`ESC` or 点击window上的小框框时）.Cocos 通过监听`director.window evenets`来获取输入。同时，为了方便`cocos.layer`自动化监听director.window evenets.我们在图层(layer)子类中设置`is_event_handler` 类 来成员为`Ture` 然后cocos 会检查图片事件响应。

在这一节中，我们将建立一步步地通过一个小项目来学习。这个小项目将展示那些键被按下那些鼠标的位置和点击。在运行这些项目前先阅读下面的代码来获得一个清晰的思路来思考我们如何来尝试写作代码。

### 键盘事件

我们开始定义`KeyDisplay layer `class.当然，我们在`__init__`做了一些初始化，在下面的代码中展示了我们的步骤：

```python
class KeyDisplay(cocos.layer.Layer):

    # If you want that your layer receives director.window events
    # you must set this variable to 'True'
    is_event_handler = True

    def __init__(self):

        super( KeyDisplay, self ).__init__()

        self.text = cocos.text.Label("", x=100, y=280 )

        # To keep track of which keys are pressed:
        self.keys_pressed = set()
        self.update_text()
        self.add(self.text)

    def update_text(self):
        key_names = [pyglet.window.key.symbol_string (k) for k in self.keys_pressed]
        text = 'Keys: '+','.join (key_names)
        # Update self.text
        self.text.element.text = text
```

这是一个定义`key_passed`的集，这应该是任何时候按下的一组键。然后，这些代码依然是没有作用的。我们应该告诉图层，当我们某键被按下或释放时要更新这一个字符集。换句话说，我们需要添加一个事件句柄在图层中。添加事件句柄在图层中仅仅需要在添加一个方法，让其被某个事件被调用。这里有俩个事件可以被我们选择 `on_key_press` and `on_key_release`:

```python
def on_key_press (self, key, modifiers):
    """This function is called when a key is pressed.
    'key' is a constant indicating which key was pressed.
    'modifiers' is a bitwise or of several constants indicating which
        modifiers are active at the time of the press (ctrl, shift, capslock, etc.)
    """

    self.keys_pressed.add (key)
    self.update_text()

def on_key_release (self, key, modifiers):
    """This function is called when a key is released.

    'key' is a constant indicating which key was pressed.
    'modifiers' is a bitwise or of several constants indicating which
        modifiers are active at the time of the press (ctrl, shift, capslock, etc.)

    Constants are the ones from pyglet.window.key
    """

    self.keys_pressed.remove (key)
    self.update_text()

def update_text(self):
    key_names = [pyglet.window.key.symbol_string (k) for k in self.keys_pressed]
    text = 'Keys: '+','.join (key_names)
    # Update self.text
    self.text.element.text = text
```

通过这样的代码，图层现在已经能充分地工作。你看可以通过按下或松开键盘，将看到任何时候图层将会展示你操作的键。

### 键盘事件样码

```python
import cocos
from cocos.actions import *
import pyglet

class KeyDisplay(cocos.layer.Layer):

    # If you want that your layer receives director.window events
    # you must set this variable to 'True'
    is_event_handler = True

    def __init__(self):

        super( KeyDisplay, self ).__init__()

        self.text = cocos.text.Label("", x=100, y=280 )

        # To keep track of which keys are pressed:
        self.keys_pressed = set()
        self.update_text()
        self.add(self.text)

    def update_text(self):
        key_names = [pyglet.window.key.symbol_string (k) for k in self.keys_pressed]
        text = 'Keys: '+','.join (key_names)
        # Update self.text
        self.text.element.text = text
    def on_key_press (self, key, modifiers):
        """This function is called when a key is pressed.
    'key' is a constant indicating which key was pressed.
    'modifiers' is a bitwise or of several constants indicating which
        modifiers are active at the time of the press (ctrl, shift, capslock, etc.)
        """

        self.keys_pressed.add (key)
        self.update_text()

    def on_key_release (self, key, modifiers):
        """This function is called when a key is released.

    'key' is a constant indicating which key was pressed.
    'modifiers' is a bitwise or of several constants indicating which
        modifiers are active at the time of the press (ctrl, shift, capslock, etc.)

    Constants are the ones from pyglet.window.key
        """

        self.keys_pressed.remove (key)
        self.update_text()

def main():
    cocos.director.director.init()
    hello_layer =KeyDisplay( )
    #hello_layer.do( RotateBy(360, duration=10) )
    # A scene that contains the layer hello_layer
    main_scene = cocos.scene.Scene (hello_layer)

    # And now, start the application, starting with main_scene
    cocos.director.director.run (main_scene)
    cocos.director.event




if __name__ == '__main__':
    main()
```

### 鼠标事件

处理鼠标输入的过程是相似的。我们可以有三个事件来供我们选择：on_mouse_press, on_mouse_motion and on_mouse_drag。接着我们就可以定义我们的图层：

```python
class MouseDisplay(cocos.layer.Layer):

    is_event_handler = True     #: enable director.window events

    def __init__(self):
        super( MouseDisplay, self ).__init__()

        self.posx = 100
        self.posy = 240
        self.text = cocos.text.Label('No mouse events yet', font_size=18, x=self.posx, y=self.posy )
        self.add( self.text )

    def update_text (self, x, y):
        text = 'Mouse @ %d,%d' % (x, y)
        self.text.element.text = text
        self.text.element.x = self.posx
        self.text.element.y = self.posy
```

然后我们添加事件句柄让其在我们text随着我们鼠标的移动而更新同时在我们按钮被点击时改变我们text的位置。

```python
def on_mouse_motion (self, x, y, dx, dy):
    """Called when the mouse moves over the app window with no button pressed

    (x, y) are the physical coordinates of the mouse
    (dx, dy) is the distance vector covered by the mouse pointer since the
      last call.
    """
    self.update_text (x, y)

def on_mouse_drag (self, x, y, dx, dy, buttons, modifiers):
    """Called when the mouse moves over the app window with some button(s) pressed

    (x, y) are the physical coordinates of the mouse
    (dx, dy) is the distance vector covered by the mouse pointer since the
      last call.
    'buttons' is a bitwise or of pyglet.window.mouse constants LEFT, MIDDLE, RIGHT
    'modifiers' is a bitwise or of pyglet.window.key modifier constants
       (values like 'SHIFT', 'OPTION', 'ALT')
    """
    self.update_text (x, y)

def on_mouse_press (self, x, y, buttons, modifiers):
    """This function is called when any mouse button is pressed

    (x, y) are the physical coordinates of the mouse
    'buttons' is a bitwise or of pyglet.window.mouse constants LEFT, MIDDLE, RIGHT
    'modifiers' is a bitwise or of pyglet.window.key modifier constants
       (values like 'SHIFT', 'OPTION', 'ALT')
    """
    self.posx, self.posy = director.get_virtual_coordinates (x, y)
    self.update_text (x,y)
```

这有点不同的是这里调用了`director.get_virtual_coordinates (x, y)`.在解释这个之前，cocos已经有两个坐标参考系，一个是物理坐标参考系一个是虚拟坐标参考系。鼠标事件句柄（mouse event handlers）会依赖于pyglet在物理坐标参考系中获取参数。如果你在虚拟坐标系中获得参数或将物理坐标系映射在虚拟坐标系中，你可能需要借助` director.get_virtual_coordinates`来进行物理坐标系与虚拟坐标系之间的映射。假如你加载了`self.posx`,`self.posy`在`on_mouse_press handler`事件中，你可以查看查询似乎是在工作的，但是如果你改变窗口的大小，这个点击次数显示将会跑到一个错误的地方上去。

对于我们已经使用的鼠标事件而言，它们是其他有用的鼠标事件：

on_mouse_release : 在一个按钮被释放的时候被调用。

on_mouse_scroll ：在鼠标滑轮移动时候被调用。

on_mouse_leave : 在鼠标移出窗口时候被调用。

on_mouse_enter：在鼠标移进窗口时被调用。

这个演示没有更多的代码了，除了一个场景中包含了两个图层然后运行它：

```python
director.init(resizable=True)
# Run a scene with our event displayers:
director.run( cocos.scene.Scene( KeyDisplay(), MouseDisplay() ) )
```

在这个场景中这些需求，可以去自己实现下：

- 改变`on_mouse_press`句柄取消虚拟坐标系映射，注意改动后窗口大小后的奇怪变化
- 注意屏幕上的鼠标坐标是物理坐标，所以在改变窗口大小时它们也会改变，修改演示以显示虚拟坐标。
- 修改代码使拖动鼠标时可以移动鼠标坐标标签
- 更改代码，以便键盘显示也显示每次设置的修饰符

## Where to next?

本章中给出的例子应该给你足够的 开始编写简单的拱廊和point-and-click-based信息 游戏。

本编程指南的其余部分进入技术细节 关于可可的一些特性。 开始时,推荐 你浏览每一章的开始而不是试图阅读 从开始到结束整个指南。

实现2 d最优性能 你需要直接使用OpenGL应用程序。 规范化 OpenGL的引用 [OpenGL编程指南 ](http://opengl.org/documentation/books/#the_opengl_programming_guide_the_official_guide_to_learning_opengl_version)和 [OpenGL着色语言 ](http://opengl.org/documentation/books/#the_opengl_shading_language_2nd_edition)。

因为是cocos2d使用pyglet您还应当检查 [pyglet编程指南 ](http://pyglet.org/doc/programming_guide/)和 [pyglet API参考](http://pyglet.org/doc/api/)

有许多是cocos2d应用的例子 `样品/ `目录的文档和源代码发行版。 保持检查 [http://www.cocos2d.org/ ](http://www.cocos2d.org/)更多的例子和教程写的。



文献来源：http://python.cocos2d.org/doc/programming_guide/quickstart.html
