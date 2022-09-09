from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from api.models import *
from .models import *
import json
# Create your tests here.

class ChallengeTests(APITestCase):
        def test_create_challenge(self):
            """
            Ensure we can create a new challenge object.
            """
            self.user = User.objects.create_user(username='user', email = 'user@gmail.com', password = 'pass')
            refresh = RefreshToken.for_user(self.user)

            self.industry = Industry.objects.create(name="Electricity")

            print(self.user.id, self.industry.name)

            self.client = APIClient()
            # self.client.credentials(HTTP_AUTHORIZATION=f'JWT {refresh.access_token}')
            self.client.force_authenticate(self.user)

            # url = reverse('challenge-list')
            data ={
                "challenge_title": "Roshani Debugger Loreum Ipsum",
                "challenge_description": "Roshani TEst Pentagon The dummy desciption of Postman Testing Tittle",
                "challenge_location": "King Kong",
                # "industry": [1, 4],
                "industry": [self.industry.id],
                "skills": "Django, React"
            }

            print(data)

            response = self.client.post('/api/challenge/', data, format=json)
            # response = self.client.post('/api/challenge/', rosh_data, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
