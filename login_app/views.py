from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from .models import User
import bcrypt

def index(request):
    # if 'user_id' not in request.session:
    #     messages.error("Please log in.")
    #     return redirect('/')
    return render(request, 'index.html')

def register(request):
    if request.method == 'POST':
        errors = User.objects.validate_registration(request.POST)

    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value)
        return redirect('/')
    else:
        form_password = request.POST['password']
        pw_hash = bcrypt.hashpw(form_password.encode(), bcrypt.gensalt()).decode()

        created_user = User.objects.create(
            first_name = request.POST['first_name'],
            last_name = request.POST['last_name'],
            email = request.POST['email'],
            password = pw_hash
            )

        request.session['user_id'] = created_user.id


        messages.success(request, "Registration was successful, please login!")
        return redirect('/')

def login(request):
    if request.method == 'POST':
        errors = User.objects.validate_login(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
        else:
            user = User.objects.get(email=request.POST['login_email'])
            request.session['user_id'] = user.id

            print('User ID:', user.id)
            return redirect('/success')

def success(request):
    print("Success!")

    if 'user_id' not in request.session:
        messages.success(request, 'Please log in!')
        return redirect('/')
    else:
        user_id = request.session['user_id']

        context = {
            'loggedin_user': User.objects.get(id=user_id)
        }

        print('Successfully logged in!')
        return render(request, 'success.html', context)

def logout(request):
    request.session.clear()

    print("Logged Out!")
    messages.success(request, "You have been logged out!")
    return redirect('/')