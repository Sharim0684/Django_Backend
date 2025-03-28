from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/linkedin_auth/", include("linkedin_auth.urls")), 
    path("api/linkedin_api/", include("linkedin_api.urls")), 
  
]
