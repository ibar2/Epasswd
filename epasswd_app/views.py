from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest, JsonResponse
from . import forms, models
from hashlib import sha1
import secrets
import requests
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
    if request.method == 'POST':
        password = request.POST.get('password', None)
        hsh = sha1(password.encode())
        hashed = hsh.hexdigest()
        res = requests.get(f'https://api.pwnedpasswords.com/range/{hashed[:5]}')
        if res.status_code == 200:
            for line in res.content.decode().splitlines():
                hash, count = line.split(":")
                if str(hash) in str(hashed).upper():
                    return JsonResponse({'result': 'this password is pwned'.upper(),
                                         'coloring': 'color: red'})
        # Check password strength criteria
        length_ok = len(password) >= 8
        uppercase_ok = any(c.isupper() for c in password)
        lowercase_ok = any(c.islower() for c in password)
        digits_ok = any(c.isdigit() for c in password)
        symbols_ok = any(
            c in '!@#$%^&*()_+-=[]{}|\\;\':",./<>?' for c in password)

        if length_ok and uppercase_ok and lowercase_ok and digits_ok and symbols_ok:
            response_data = {'result': 'this is Strong password'.upper(),
                             'coloring': 'color: blue'}
        else:
            response_data = {'result': 'This is a Very weak password'.upper(),
                             'coloring': 'color: red'}

        return JsonResponse(response_data)

    return render(request, 'pages/password_strength_checker.html')


def SavePassword(request):
    # saving passwords
    return render(request, 'pages/savepasswords.html')


def dashboard(request):
    # dashboard
    if request.user.is_authenticated:

        return render(request, 'pages/dashboard.html')
    return redirect('/signin')

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


def getval(request):
    return redirect('/')
