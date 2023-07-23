from django.shortcuts import render, HttpResponse


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


def login(request):
    # login existing users
    return HttpResponse('loged')


def signup(request):
    # create new users
    return HttpResponse('created')
