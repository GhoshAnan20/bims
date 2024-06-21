from django.contrib import admin
from django.urls import path, include
from bimsapp import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name = "home"),
    path('register', views.register, name = "register"),
    path('log_in', views.log_in, name = "log_in"),
    path('about', views.about, name = "about"),
    path('contact', views.contact, name = "contact"),
    path('forgot', views.forgot, name = "forgot"),
    path('reset/<forgot_token>', views.reset, name = "reset"),
    path('dashboard', views.dashboard, name = "dashboard"),
    path('log_out', views.log_out, name = 'log_out'),
    path('upload', views.upload, name = "upload"),
    path('form', views.form, name = "form"),
    path('account', views.account, name = "account"),
    path('verify/<auth_token>', views.verify, name = "verify" ),
    path('log_in/', auth_views.LoginView.as_view(template_name='log_in.html'), name='log_in'),
    


]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

