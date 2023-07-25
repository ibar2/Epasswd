from django.shortcuts import render, HttpResponse, redirect
from django.http import HttpResponseBadRequest
from . import forms, models
from django.contrib.auth import login, authenticate


def home(request):
    return render(request, 'pages/home.html')


def generator(request):
    # generating staff
    return HttpResponse('under construction')


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
        redirect('/logout')
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


def logout(request):
    return HttpResponse('logout')
