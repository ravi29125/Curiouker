from django.urls import path
from . import views

urlpatterns=[
    path('',views.loginpage,name='loginpage'),
    path('signin',views.signinpage,name='signinpage'),
    path('home',views.getHashup,name='homepage'),
    path('',views.logout_page,name="log"),
    path('copy',views.showpass,name='shoPass'),
    path('pass',views.password,name='pass'),
]