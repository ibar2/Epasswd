from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home_page'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('generator/', views.generator, name='generator'),
    path('generate/', views.generate, name='generate'),
    path('addpass/', views.SavePassword, name='addpass'),
    path('checker/', views.passwordchecking, name='password_checking'),
    path('signin/', views.signin, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.signout, name='logout'),
    path('getval/', views.getval, name='getval'),
    path('settings/', views.settings, name='settings')
]
