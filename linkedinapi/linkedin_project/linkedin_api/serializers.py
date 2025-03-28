from rest_framework import serializers

# Serializer for handling LinkedIn OAuth authorization
class LinkedInAuthSerializer(serializers.Serializer):
    code = serializers.CharField(required=True)

# Serializer for handling LinkedIn access tokens
class LinkedInTokenSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

# Serializer for handling LinkedIn user profile responses
class LinkedInProfileSerializer(serializers.Serializer):
    id = serializers.CharField()
    firstName = serializers.DictField()
    lastName = serializers.DictField()
    localizedFirstName = serializers.CharField()
    localizedLastName = serializers.CharField()
    profilePicture = serializers.DictField(required=False)

# Serializer for handling LinkedIn post requests
class LinkedInPostSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    message = serializers.CharField(required=True)
