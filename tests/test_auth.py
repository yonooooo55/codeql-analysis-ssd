import unittest
from app import app

class AuthRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_login_page_loads(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Login", response.data)

    def test_invalid_login(self):
        response = self.client.post('/login', data={
            'email': 'fake@example.com',
            'password': 'wrongpassword'
        })
        self.assertIn(b'Invalid', response.data)  # adjust based on actual error msg

if __name__ == '__main__':
    unittest.main()