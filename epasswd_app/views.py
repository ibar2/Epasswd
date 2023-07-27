from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest, JsonResponse
from . import forms, models
from hashlib import sha1
from .Hashers import hasher
from django.contrib.auth import login, authenticate, logout
import secrets
import requests
import os


# helper function for the save password
def split_string(string):
    if len(string) % 2 == 0:
        middle = len(string) // 2
        return string[:middle], string[middle:]
    else:
        middle = len(string) // 2
        return string[:middle], string[middle:]


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
        # api request to haveibeenpwned to check if the password is pwned
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
    if request.user.is_authenticated:
        if request.method == 'POST':
            name = request.POST['name']
            passwd = request.POST['pass']
            getkey = models.hashers.objects.get(userpk=request.user.pk).key
            encryptedata, tag, nonce = hasher.encrypt(getkey, passwd)
            part1, part2 = split_string(encryptedata)
            mod = models.passwords.objects.create(
                owner=request.user.pk, name=name, passwd=part1, tag=tag, nonce=nonce)
            mod.save()
            partialmodel = models.partialpass.objects.create(
                partof=mod.pk, partial=part2, owner=request.user.pk)
            partialmodel.save()
        passmodel = models.passwords.objects.filter(owner=request.user.pk)
        names = {}
        for passobject in passmodel:
            names[passobject.name] = None
        return render(request, 'pages/savepasswords.html', {'passwords': names})
    else:
        return redirect('/signin')


def dashboard(request):
    # dashboard
    if request.user.is_authenticated:
        part1 = models.passwords.objects.filter(
            owner=request.user.pk)
        if request.GET.get('q', False):
            part1 = part1.filter(name__contains=request.GET.get('q'))
        texts = {}
        idforv = 0
        for p1 in part1:
            texts[p1.name] = idforv
            idforv += 1
        return render(request, 'pages/dashboard.html', {'passwords': texts})
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
                # generating and storing encryption key at the signup of the user
                key = os.urandom(16)
                user_encryption_key = models.hashers.objects.create(userpk=user.pk,
                                                                    key=key)
                user_encryption_key.save()
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
    if request.user.is_authenticated:
        name = request.GET.get('val', False)
        if name:
            getkey = models.hashers.objects.get(userpk=request.user.pk).key
            p1 = models.passwords.objects.get(name=name)
            p2 = models.partialpass.objects.get(partof=p1.pk)
            data = p1.passwd + p2.partial
            decrypt = hasher.decrypt(getkey, data, p1.tag, p1.nonce)
            return JsonResponse({'val': decrypt.decode()})
        else:
            return JsonResponse({'val': 'not exists'})

    else:
        return redirect('/sigin')


def settings(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            wrongpassword = False
            didnotmatch = False
            current = request.POST['currentpass']
            newpassword = request.POST['newpassword']
            newpassword2 = request.POST['newpassword2']
            if newpassword == newpassword2:
                print(request.user.username)
                user = models.User.objects.get(username=request.user.username)
                if user.check_password(current):
                    user.set_password(newpassword)
                    user.save()
                    redirect('/signin')
                else:
                    wrongpassword = True
            else:
                didnotmatch = True

            return render(request, 'pages/settings.html', {
                'wrong': wrongpassword,
                'didnotmatch': didnotmatch
            })
        return render(request, 'pages/settings.html')

    return redirect('/signin')
