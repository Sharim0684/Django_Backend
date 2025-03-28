


from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import requests
from django.middleware.csrf import get_token

class LinkedInAuthURL(APIView):
    def get(self, request):
        linkedin_auth_url = (
            "https://www.linkedin.com/oauth/v2/authorization?"
            f"response_type=code&client_id={settings.LINKEDIN_CLIENT_ID}"
            f"&redirect_uri={settings.LINKEDIN_REDIRECT_URI}"
            "&scope=openid%20profile%20w_member_social%20email"
        )
        return Response({"linkedin_auth_url": linkedin_auth_url}, status=status.HTTP_200_OK)

class LinkedInCallback(APIView):
    def post(self, request):
        code = request.data.get("code")
        if not code:
            return Response({"error": "Code parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

        token_url = "https://www.linkedin.com/oauth/v2/accessToken"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.LINKEDIN_REDIRECT_URI,
            "client_id": settings.LINKEDIN_CLIENT_ID,
            "client_secret": settings.LINKEDIN_CLIENT_SECRET,
        }

        response = requests.post(token_url, data=data)
        token_data = response.json()

        if "access_token" in token_data:
            return Response(token_data, status=status.HTTP_200_OK)
        else:
            return Response(token_data, status=status.HTTP_400_BAD_REQUEST)

class LinkedInProfile(APIView):
    def get(self, request):
        access_token = request.GET.get("access_token")
        if not access_token:
            return Response({"error": "Access token is required"}, status=status.HTTP_400_BAD_REQUEST)

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get("https://api.linkedin.com/v2/me", headers=headers)
        return Response(response.json(), status=response.status_code)

class LinkedInEmail(APIView):
    def get(self, request):
        access_token = request.GET.get("access_token")
        if not access_token:
            return Response({"error": "Access token is required"}, status=status.HTTP_400_BAD_REQUEST)

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get("https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))", headers=headers)
        return Response(response.json(), status=response.status_code)

class LinkedInPost(APIView):
    def post(self, request):
        access_token = request.data.get("access_token")
        user_id = request.data.get("user_id")
        message = request.data.get("message")

        if not all([access_token, user_id, message]):
            return Response({"error": "access_token, user_id, and message are required"}, status=status.HTTP_400_BAD_REQUEST)

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "X-Restli-Protocol-Version": "2.0.0",
        }
        post_data = {
            "author": f"urn:li:person:{user_id}",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": message},
                    "shareMediaCategory": "NONE",
                }
            },
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
        }

        response = requests.post("https://api.linkedin.com/v2/ugcPosts", headers=headers, json=post_data)
        return Response(response.json(), status=response.status_code)



from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

# @csrf_exempt
# def linkedin_token(request):
#     if request.method == "POST":
#         data = json.loads(request.body)
#         code = data.get("code")

#         if not code:
#             return JsonResponse({"error": "Code not provided"}, status=400)

#         # Dummy access token response
#         return JsonResponse({
#             "access_token": "dummy_access_token_generated",
#             "expires_in": 5184000
#         })

#     return JsonResponse({"error": "Invalid request"}, status=400)


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

CLIENT_ID = "86embapip2hnsy"
CLIENT_SECRET = "WPL_AP1.UzATRB3rCrM44AYA.4sGm2g=="
REDIRECT_URI = "http://localhost:8000/api/linkedin_api/callback/"

@csrf_exempt
def linkedin_token(request):
    if request.method == "POST":
        data = json.loads(request.body)
        auth_code = data.get("code")

        if not auth_code:
            return JsonResponse({"error": "Authorization code is required"}, status=400)

        token_url = "https://www.linkedin.com/oauth/v2/accessToken"
        payload = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = requests.post(token_url, data=payload, headers=headers)
        token_data = response.json()

        if "access_token" in token_data:
            return JsonResponse(token_data)
        else:
            return JsonResponse({"error": "Failed to get access token", "details": token_data})

    return JsonResponse({"error": "Invalid request"}, status=400)



def get_csrf_token(request):
    csrf_token = get_token(request)
    response = JsonResponse({"csrfToken": csrf_token})
    response.set_cookie('csrftoken', csrf_token)  # Store CSRF token in cookies
    return response


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

# @csrf_exempt 
# def get_access_token(request):
#     if request.method == "POST":
#         return JsonResponse({"message": "Access token endpoint is working!"})
#     return JsonResponse({"error": "Invalid request"}, status=400)



# Replace these with your actual LinkedIn credentials
LINKEDIN_CLIENT_ID = "86embapip2hnsy"
LINKEDIN_CLIENT_SECRET = "WPL_AP1.UzATRB3rCrM44AYA.4sGm2g=="
REDIRECT_URI = "http://127.0.0.1:8000/api/linkedin_auth/callback/"



@csrf_exempt
def get_access_token(request):
    if request.method == "POST":
        try:
            # Check if data is JSON
            if request.content_type == "application/json":
                data = json.loads(request.body)
            else:  # If form-urlencoded, use request.POST
                data = request.POST

            grant_type = data.get("grant_type")
            client_id = data.get("client_id")
            client_secret = data.get("client_secret")
            redirect_uri = data.get("redirect_uri")
            code = data.get("code")

            if not all([grant_type, client_id, client_secret, redirect_uri, code]):
                return JsonResponse({"error": "Missing required parameters"}, status=400)

            return JsonResponse({"message": "Data received successfully!"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)




# @csrf_exempt
# def get_access_token(request):
#     if request.method == "POST":
#         try:
#             data = json.loads(request.body)  # Parse JSON data from request

#             # Extract required fields
#             grant_type = data.get("grant_type")
#             client_id = data.get("client_id")
#             client_secret = data.get("client_secret")
#             redirect_uri = data.get("redirect_uri")
#             code = data.get("code")

#             if not all([grant_type, client_id, client_secret, redirect_uri, code]):
#                 return JsonResponse({"error": "Missing required parameters"}, status=400)

#             # Step 1: Call LinkedIn API to get the access token
#             linkedin_token_url = "https://www.linkedin.com/oauth/v2/accessToken"
#             payload = {
#                 "grant_type": grant_type,
#                 "client_id": client_id,
#                 "client_secret": client_secret,
#                 "redirect_uri": redirect_uri,
#                 "code": code
#             }
#             headers = {
#                 "Content-Type": "application/x-www-form-urlencoded"
#             }

#             response = requests.post(linkedin_token_url, data=payload, headers=headers)
            
#             # Step 2: Parse LinkedIn Response
#             if response.status_code == 200:
#                 return JsonResponse(response.json(), status=200)
#             else:
#                 return JsonResponse({"error": "Failed to get access token", "details": response.json()}, status=response.status_code)

#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=400)

#     return JsonResponse({"error": "Invalid request method"}, status=405)
