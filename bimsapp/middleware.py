# middleware.py

from django.urls import reverse
from django.shortcuts import redirect

class ExcludeFromAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # List of URLs that should be excluded from authentication
        excluded_urls = [reverse('about'), reverse('contact')]

        if request.user.is_authenticated and request.path in excluded_urls:
            return self.get_response(request)  # Pass through if already authenticated

        response = self.get_response(request)
        return response
