from django.shortcuts import render,redirect

# Create your views here.
from django.views import View
from django.contrib.auth import login, authenticate
from django.contrib import messages
from .models import CustomUser

def register_view(request):
      if request.method == 'POST':
          username = request.POST['username']
          password1 = request.POST['password1']
          password2 = request.POST['password2']

          if password1 != password2:
              messages.error(request, 'Passwords do not match.')
              return render(request, 'accounts/register.html')

          if CustomUser.objects.filter(username=username).exists():
              messages.error(request, 'Username already taken.')
              return render(request, 'accounts/register.html')

          user = CustomUser.objects.create_user(
              username=username,
              password=password1,
              role='voter'
          )
          login(request, user)
          return redirect('election_list')

      return render(request, 'accounts/register.html')


def login_view(request):
      if request.method == 'POST':
          username = request.POST['username']
          password = request.POST['password']
          user = authenticate(request, username=username, password=password)

          if user is not None:
              login(request, user)
              return redirect('election_list')
          else:
              messages.error(request, 'Invalid username or password.')

      return render(request, 'accounts/login.html')

