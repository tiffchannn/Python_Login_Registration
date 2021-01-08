from django.db import models
import re
import bcrypt

# to check if sth is in database
# userExists = User.objects.filter(user=request.POST['username'])
# if usernameExists:
  # errors['user_exists'] = "User already in db!"

# use regex to check valid email!
# password regex??

# firstname and lastname > 2
# email should be valid
# pw should match
# pw at least 8 chars

class UserManager(models.Manager):
    def validate_registration(self, postData):
      errors = {}

      if len(postData['first_name']) < 2:
          errors['first_name'] = "First name must be at least 2 characters."

      if len(postData['last_name']) < 2:
          errors['last_name'] = "Last name must be at least 2 characters."

      EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
      if not EMAIL_REGEX.match(postData['email']):    # test whether a field matches the pattern
          errors['email'] = "Invalid email address!"

      # if same email is found in db, show error
      user = User.objects.filter(email=postData['email'])
      if len(user) > 0:
          print("Email already exists!")
          errors['email'] = "Email already exists."

      if postData['password'] != postData['confirm_password']:
          errors['password'] = "Passwords don't match!"
      elif len(postData['password']) < 8:
          errors['password'] = "Password must be at least 8 characters."

      return errors




    def validate_login(self, postData):
      errors = {}

      user = User.objects.filter(email=postData['login_email'])
      print('user in validate login: ', user)

      if len(User.objects.filter(email=postData['login_email'])) == 0:
        print("User was not found!")
        errors['login_email'] = "Email was not found, please register."
      else:
        if not bcrypt.checkpw(postData['login_password'].encode(), user[0].password.encode()):
          print("Passwords DON'T match!")
          errors['login_password'] = "Password was incorrect!"

      return errors


class User(models.Model):
    first_name = models.CharField(max_length=45)
    last_name = models.CharField(max_length=45)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=45)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

