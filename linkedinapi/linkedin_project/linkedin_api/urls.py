from django.urls import path
from .views import LinkedInAuthURL, LinkedInCallback, LinkedInProfile, LinkedInEmail, LinkedInPost, get_access_token, get_csrf_token, linkedin_token

urlpatterns = [
    path("auth-url/", LinkedInAuthURL.as_view(), name="linkedin_auth_url"),
    path("callback/", LinkedInCallback.as_view(), name="linkedin_callback"),
    path("profile/", LinkedInProfile.as_view(), name="linkedin_profile"),
    path("email/", LinkedInEmail.as_view(), name="linkedin_email"),
    path("post/", LinkedInPost.as_view(), name="linkedin_post"),
    path('token/', linkedin_token, name='linkedin_token'),
    path('csrf_token/',get_csrf_token,name="get_access_token"),
    path("get_access_token/", get_access_token, name="get_access_token"),
]
