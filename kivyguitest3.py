# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 22:21:15 2014

@author: kjetilwormnes
"""

#import kivy
#kivy.require('1.8.0')

from kivy.app import App
#from kivy.uix.widget import Widget
#from kivy.uix.gridlayout import GridLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.widget import Widget
from kivy.uix.dropdown import DropDown
from kivy.uix.modalview import ModalView
from kivy.uix.bubble import Bubble
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.base import runTouchApp
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.graphics import Rectangle

from functools import partial

#layout = GridLayout(cols=2, row_force_default=True, row_default_height=40)
#
#
#
#layout.add_widget(Button(text='Hello 1', size_hint_x=None, width=100))
#layout.add_widget(Button(text='World 1'))
#layout.add_widget(Button(text='Hello 2', size_hint_x=None, width=100))
#layout.add_widget(Button(text='World 2'))
#
#runTouchApp(layout)


#    def create_clock(self, widget, touch, *args):
#        callback = partial(self.menu, touch)
#        Clock.schedule_once(callback, 2)
#        touch.ud['event'] = callback
#
#    def delete_clock(self, widget, touch, *args):
#        Clock.unschedule(touch.ud['event'])

def show_pwd(x, p, touch, y=None):
#    if y == 'end':
#        x.text = 'hidden'
#    else:
#        x.text='data entry'+str(p)
    
    #print(touch.pos)# x.collide_point(*touch.pos):
    if x.collide_point(p[0], p[1]):
        print(touch.profile)
        x.text='revealed'
    else:
        Clock.unschedule(touch.ud['event'])
        del(touch.ud['event'])
#    x.text='revealed'+str(p)+str(x.collide_point(p[0], p[1]))
#        Clock.unschedule(x)
        

class MyButton(Button):
    
#    def on_press(self):
#        self.text = 'clicked'
    
#    pressed = False
    
    def __init__(self, **arg):
        self.pressed = False
        print(arg)
        super(MyButton, self).__init__(**arg)
        
    
    def siblings(self):
        siblings = []
        for k in self.parent.children:
            if not k == self:
                siblings.append(k)

        return siblings
        
    def show_pwd(self, *args):
        print('\n\nSHOW_PWD\n', args)
        #if self.collide_point(*args[0].pos):
        self.text='revealed0'
        
        for k in self.siblings():
            k.text='revealed'
        self.pressed = True
        pass


#    def on_touch_move(self, touch):
#        for s in self.siblings():
#            s.state = 'down'
        
    
    def on_touch_down(self, touch):
                
        super(MyButton, self).on_touch_down(touch)
        
        if self.collide_point(touch.pos[0], touch.pos[1]):
            print('\n\nTOUCH DOWN\n',touch)
#            p = (touch.pos[0],touch.pos[1]) 
#            print(p)
            if touch.is_double_tap:
                self.text = 'double tapped'
#                if 'event' in touch.ud:
#                    del(touch.ud['event'])
            elif touch.is_triple_tap:
                self.text= 'triple tapped'
#                if 'event' in touch.ud:
#                    del(touch.ud['event'])
                self.add_widget(TextInput())
            else:
                callback = partial(self.show_pwd, touch)
#                Clock.schedule_once(callback, 2)
                Clock.schedule_once(callback, 1)
                touch.ud['event'] = callback
                
                for s in self.siblings():
                    s.state = self.state
                
    
    def on_touch_up(self, touch):
        super(MyButton, self).on_touch_up(touch)
        if self.collide_point(*touch.pos):
            print('\n\nTOUCH_UP\n', touch)
        
        for s in self.siblings():
            s.state = self.state

        if self.pressed:
            self.text='hidden again0'
            
            for k in self.siblings():
                k.text = 'hidden again'

        
        if 'event' in touch.ud:
            Clock.unschedule(touch.ud['event'])

        self.pressed = False        
        
        #print(touch.ud.keys())
        #if 'event' in touch.ud:# and not (touch.is_double_tap or touch.is_triple_tap):
        #    Clock.unschedule(touch.ud['event'])#('end')
        #    del(touch.ud['event'])
        #    self.text='hidden again'


class KivyTestApp(App):
    
    def build(self):
        layout = GridLayout(cols=2,spacing=2, size_hint_y=None,  row_default_height=Window.height/8, row_force_default=True)

        # Make sure the height is such that there is something to scroll.
        layout.bind(minimum_height=layout.setter('height'))
        for i in range(50):
            sublayout = GridLayout(cols=4,spacing=2)
            layout.add_widget(Label(text=str(i), size_hint_x=None, width=Window.width/20))
            sublayout.add_widget(MyButton(text='Desc %d'%(i)))
            sublayout.add_widget(MyButton(text='Uname %d'%(i)))
            sublayout.add_widget(MyButton(text='Pwd %d'%(i)))    
            layout.add_widget(sublayout)
        
        root=GridLayout(cols=1)#size_hint=(None, None), size=(400, 400))
        hdrlayout = GridLayout(cols=4, spacing=2,  height=Window.height/12, size_hint_y=None)
        hdrlayout.add_widget(Label(text='#', size_hint_x=None, width=Window.width/20))
        hdrlayout.add_widget(Label(text='Description'))
        hdrlayout.add_widget(Label(text='User name'))
        hdrlayout.add_widget(Label(text='Password'))

        #hdrlayout.add_widget(Label(text='...', size_hint_x=None, width=Window.width/20))
#        s = Label(text='...')
#        s.bind(press=self.display_settings(settings))
#        hdrlayout.add_Widget(settings, size_hint_x=None, width = Window.width/20)
        
        
        
        root.add_widget(hdrlayout)

        sview = ScrollView()
        sview.add_widget(layout)
        root.add_widget(sview)
        
        root0 = FloatLayout()
        root0.add_widget(root)
        
        def blah(x):
            print(x.text)



        dropdown = ModalView(anchor_y='top',  size_hint_x = .5, size_hint_y=None, height=Window.height/12*11)
        dropdown.add_widget(Button(text='test1', size_hint_y=None, height='1cm', on_release=blah))        
        #dropdown.add_widget(Button(text='test2', size_hint_y=None, height='1cm'))  
        
        #with dropdown.canvas:
#            Color(1., 1., 0)
        #    Rectangle(size=(350, 350))


        self.locklbl=Label(text='[size=12sp][b]UN[/b]locked[/size]', halign='right', markup=True, size_hint_x=None, width=100, size_hint_y = None, height=24)
        albl=AnchorLayout(anchor_x='right', anchor_y='bottom')
        albl.add_widget(self.locklbl)
        root0.add_widget(albl) 


        def open_settings(it, touch):
            dropdown.open(settingsanchor)
            dropdown.pos[0] = Window.width/2
            dropdown.pos[1] = 0
            

        settingslbl = Label(text='[b]...[/b]', halign='right', markup=True, size_hint_x=None, width=50, size_hint_y = None, height=Window.height/12)
        settingsanchor = Widget(size_hint_x=.5, size_hint_y=None, height=Window.height/12)        
        settingslbl.bind(on_touch_up=open_settings)#lambda a,b: dropdown.open(settingsanchor))

        albl2=AnchorLayout(anchor_x='right', anchor_y='top')
        albl2.add_widget(settingslbl)
        albl2.add_widget(settingsanchor)
        root0.add_widget(albl2) 
        

        
        
        
        
        return root0

#    def build_config(self, config):
#        pass
#        #config.add_section('kinect')
#        #config.set('kinect', 'index', '0')
#        #config.add_section('shader')
#        #config.set('shader', 'theme', 'rgb')
#    
#    def build_settings(self, settings):
#        settings.add_json_panel('Password Locker', self.config, data='''[
#            { "type": "title", "title": "Kinect" },
#            { "type": "numeric", "title": "Index",
#              "desc": "Kinect index, from 0 to X",
#              "section": "kinect", "key": "index" },
#            { "type": "title", "title": "Shaders" },
#            { "type": "options", "title": "Theme",
#              "desc": "Shader to use for a specific visualization",
#              "section": "shader", "key": "theme",
#              "options": ["rgb", "hsv", "points"]}
#        ]''')


if __name__ == '__main__':
    
    KivyTestApp().run()

#layout = GridLayout(cols=2,spacing=2, size_hint_y=None,  row_default_height=Window.height/8, row_force_default=True)
#
## Make sure the height is such that there is something to scroll.
#layout.bind(minimum_height=layout.setter('height'))
#for i in range(50):
#    sublayout = GridLayout(cols=4,spacing=2)
#    layout.add_widget(Label(text=str(i), size_hint_x=None, width=Window.width/20))
#    sublayout.add_widget(MyButton(text='Desc %d'%(i)))
#    sublayout.add_widget(MyButton(text='Uname %d'%(i)))
#    sublayout.add_widget(MyButton(text='Pwd %d'%(i)))    
#    layout.add_widget(sublayout)
#
#root = GridLayout(cols=1)#size_hint=(None, None), size=(400, 400))
#hdrlayout = GridLayout(cols=4, spacing=2,  height=Window.height/12, size_hint_y=None)
#hdrlayout.add_widget(Label(text='#', size_hint_x=None, width=Window.width/20))
#hdrlayout.add_widget(Label(text='Description'))
#hdrlayout.add_widget(Label(text='User name'))
#hdrlayout.add_widget(Label(text='Password'))
#root.add_widget(hdrlayout)
#
#sview = ScrollView()
#sview.add_widget(layout)
#root.add_widget(sview)
#
#runTouchApp(root)


#   def build_config(self, config):
#        config.add_section('kinect')
#        config.set('kinect', 'index', '0')
#        config.add_section('shader')
#        config.set('shader', 'theme', 'rgb')
#
#    def build_settings(self, settings):
#        settings.add_json_panel('Kinect Viewer', self.config, data='''[
#            { "type": "title", "title": "Kinect" },
#            { "type": "numeric", "title": "Index",
#              "desc": "Kinect index, from 0 to X",
#              "section": "kinect", "key": "index" },
#            { "type": "title", "title": "Shaders" },
#            { "type": "options", "title": "Theme",
#              "desc": "Shader to use for a specific visualization",
#              "section": "shader", "key": "theme",
#              "options": ["rgb", "hsv", "points"]}
#        ]''')