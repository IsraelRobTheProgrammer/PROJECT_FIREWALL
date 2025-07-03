from django.test import TestCase
from django.contrib.auth import get_user_model
# Create your tests here.


class UserManagersTestCase(TestCase):
    """
    Test case for user managers.
    """

    def test_create_user(self):
        """
        Test creating a user with valid data.
        """
        User = get_user_model()
        user = User.objects.create_user(
            email="test_email@user.com", password="test_password"
        )
        self.assertEqual(user.email, "test_email@user.com")
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        try:
            self.assertIsNone(user.username)
        except AttributeError:
            # If the User model does not have a username field, this is expected
            pass
        with self.assertRaises(ValueError):
            User.objects.create_user(email="", password="test_password")
        with self.assertRaises(TypeError):
            User.objects.create_user()
        with self.assertRaises(TypeError):
            User.objects.create_user(email="")

    def test_create_superuser(self):
        """
        Test creating a superuser with valid data.
        """
        User = get_user_model()
        superuser = User.objects.create_superuser(
            email="super@user.com", password="super_password"
        )

        self.assertEqual(superuser.email, "super@user.com")
        self.assertTrue(superuser.is_active)
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)
        try:
            self.assertIsNone(superuser.username)
        except AttributeError:
            # If the User model does not have a username field, this is expected
            pass
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                email="super@user.com", password="super_password", is_superuser=False
            )
