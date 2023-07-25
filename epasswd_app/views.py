from django.shortcuts import render, HttpResponse, redirect
from django.http import HttpResponseBadRequest, JsonResponse
from . import forms, models
from hashlib import sha1
import secrets
# import requests
from django.contrib.auth import login, authenticate, logout


def home(request):
    return render(request, 'pages/home.html')


def generator(request):
    # return the page
    return render(request, 'pages/generator.html')


def generate(request):
    # generates the password
    v = [secrets.choice("abcdefghijklmnopqrstuvwxyz-@#$&^!\
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ?_*,;")
         for _ in range(12)]
    v[secrets.choice(range(12))] = secrets.choice('1,2,3,4,5,6,7,8,9')
    return JsonResponse({'password': "".join(v)})


def passwordchecking(request):
    # password strength checker
    return HttpResponse('.....')


def SavePassword(request):
    # saving passwords
    return HttpResponse('under construction')


def dashboard(request):
    # dashboard
    return HttpResponse('Dashboard loading.....')


def signup(request):
    # create new users
    if request.user.is_authenticated:
        logout(request)
        return redirect('/signup')
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        retryPassword = request.POST['password2']
        if password == retryPassword:
            signupform = forms.SignUpForm(request.POST)
            if signupform.is_valid():
                user = models.User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                user.save()
                login(request, user)
                return redirect('/dashboard')
            return HttpResponseBadRequest('please check if you  provided the correct\
                                           username, email, and password')
        return render(request, 'pages/signup.html', {'pass_not_equal': True})
    return render(request, 'pages/signup.html')


def signin(request):
    # login existing users
    if request.method == 'POST':
        if request.user.is_authenticated:
            logout(request)
        user = authenticate(
            username=request.POST['username'], password=request.POST['password'])
        username44 = request.POST['username']
        if user is not None:
            login(request, user)
            return redirect('/dashboard')
        else:
            return render(request, 'pages/signin.html', {'notfoound': True,
                                                         'usernameff': username44})

    return render(request, 'pages/signin.html')


def signout(request):
    if request.user.is_authenticated:
        logout(request)
        return redirect('/')
    return redirect('/')
