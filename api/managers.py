from django.contrib.auth.base_user import BaseUserManager


class CustomUserManager(BaseUserManager):
    def create_user(self, email, username=None, password=None, password2=None):
        if not email:
            raise ValueError("The email must be set")
        if not password:
            raise ValueError("The password must be set")
        email = self.normalize_email(email)

        user = self.model(email=email)
        if username is None:
            user.username = email.split('@')[0]
        else:
            user.username = username
        # user.username = username
        # user.role = role
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username=None, password=None):
        user = self.create_user(email, username, password=password)
        # user.role.add(5)
        user.is_staff = True

        # if user.role != 1:
        #     raise ValueError("Superuser must have role of God/Global level Admin")
        user.save(using=self._db)
        return user
