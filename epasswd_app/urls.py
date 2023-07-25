from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home_page'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('generator/', views.generator, name='generator'),
    path('addpass/', views.SavePassword, name='addpass'),
    path('checker/', views.passwordchecking, name='password_checking'),
    path('signin/', views.signin, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout, name='logout')
]
