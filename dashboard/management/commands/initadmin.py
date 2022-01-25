from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User

def createSuperUser(username, password, email = "", firstName = "", lastName = ""):
    invalidInputs = ["", None]

    if username.strip() in invalidInputs or password.strip() in invalidInputs:
        return None

    user = User(
        username = username,
        email = email,
        first_name = firstName,
        last_name = lastName,
    )
    user.set_password(password)
    user.is_superuser = True
    user.is_staff = True
    user.save()

    return user

def createSimpleUser(username, password, email = "", firstName = "", lastName = ""):
    invalidInputs = ["", None]

    if username.strip() in invalidInputs or password.strip() in invalidInputs:
        return None

    user = User(
         username = username,
         email = email,
         first_name = firstName,
         last_name = lastName,
     )
    user.set_password(password)
    user.is_superuser = False
    user.is_staff = False
    user.save()

    return user

class Command(BaseCommand):

    def handle(self, *args, **options):
        Account = get_user_model()
        if Account.objects.count() == 0:
            try:
                createSuperUser("admin", "password", email = "", firstName = "NAME", lastName = "SURNAME")
                createSimpleUser("user", "password", email = "", firstName = "NAME", lastName = "SURNAME")
            except:
                print("Could not create the admin and user accounts")
        else:
            print('User&Admin accounts can only be initialized if no Accounts exist')
