import requests

def get_linkedin_email(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    email_url = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
    response = requests.get(email_url, headers=headers)
    return response.json() if response.status_code == 200 else None
