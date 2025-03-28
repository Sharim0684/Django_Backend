from django.db import models

class LinkedInUser(models.Model):
    linkedin_id = models.CharField(max_length=50, unique=True)
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(unique=True, blank=True, null=True)
    profile_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)  # Store when user first logged in
    updated_at = models.DateTimeField(auto_now=True)  # Store when user last updated info

    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.email}"
