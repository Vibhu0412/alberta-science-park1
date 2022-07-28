from django.test import TestCase
from .models import User, UserRole

# Create your tests here.
class FirstTest(TestCase):
    def setUp(self) -> None:
        self.role = UserRole.objects.create(id=2)