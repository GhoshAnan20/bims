from django.shortcuts import render, redirect, HttpResponse, get_object_or_404
from django.contrib.auth import authenticate, logout, login
from django.contrib import messages
from bimsapp.models import *
from bimsapp.forms import *
from datetime import datetime
import uuid
from django.core.mail import send_mail
from django.conf import settings
import csv
from django.urls import reverse
import pytesseract
from PIL import Image
import csv
from itertools import islice
import re
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse


# Create your views here.
def home(request):
    return render(request, "home.html")


def register(request):
    try:
        if request.method == "POST":
            username = request.POST.get('username')
            firstname = request.POST.get('firstname')
            lastname = request.POST.get('lastname')
            email = request.POST.get('email')
            password = request.POST.get('password')
            confirmpass = request.POST.get('confirmpass')

            # Validations
            if User.objects.filter(username=username):
                messages.error(request, "Username already exists")
                return redirect('register') + f'?error=username'
            if User.objects.filter(email=email):
                messages.error(request, "Email already exists")
                return redirect('register') + f'?error=email'
            if len(username) > 15:
                messages.error(request, "Username must be under 10 characters")
                return redirect('register') + f'?error=username'
            if password != confirmpass:
                messages.error(request, "Passwords don't match")
                return redirect('register') + f'?error=password'
            if not username.isalnum():
                messages.error(request, "Username should only contain alphanumeric characters")
                return redirect('register') + f'?error=username'
            if not is_strong_password(password):
                messages.error(request, "Enter a strong password")
                return redirect('register') + f'?error=password'
        
            
            myuser = User.objects.create_user(username, email, password)
            myuser.first_name = firstname
            myuser.last_name = lastname
            myuser.save()
            auth_token = str(uuid.uuid4())
            profile_obj = Profile.objects.create(user=myuser, auth_token=auth_token)
            profile_obj.save()
            send_mail_after_registration(email, auth_token)

            return redirect("form")

    except Exception as e:
        print(e)
        messages.error(request, "Sorry! We encountered some error. Please try again later.")

    return render(request, "register.html")

def form(request):
    try:
        if request.method == "POST":
            firstName = request.POST.get('firstName')
            middleName = request.POST.get('middleName')
            lastName = request.POST.get('lastName')
            dob = request.POST.get('dob')
            dob = datetime.strptime(dob, '%Y-%m-%d')
            dob_formatted = dob.strftime('%d/%m/%Y')

            gender = request.POST.get('gender')
            motherName = request.POST.get('motherName')
            fatherName = request.POST.get('fatherName')
            aadhaarNumber = request.POST.get('aadhaarNumber')
            contactNumber = request.POST.get('contactNumber')
            panNumber = request.POST.get('panNumber')

            if not single_word(firstName):
                messages.info(request, "First Name should contain only a single word.")
                return redirect('form')

            # if not single_word(middleName):
            #     messages.info(request, "Middle Name should contain only a single word.")
            #     return redirect('form')
            
            if not single_word(lastName):
                messages.error(request, "Last Name should contain only a single word.")
                return redirect('form')
            
            if not single_word(motherName):
                messages.error(request, "Mother Name should contain only a single word.")
                return redirect('form')
            
            if not single_word(fatherName):
                messages.error(request, "Father Name should contain only a single word.")
                return redirect('form')
            
            if not is_digit(contactNumber):
                messages.error(request, "Invalid Contact Number.")
                return redirect('form')
            
            if not validate_aadhaar_number(aadhaarNumber):
                messages.error(request, "Aadhaar Number entered is invalid.")
                return redirect('form')
            
            if not validate_pan_number(panNumber, lastName):
                messages.error(request, "PAN Number entered is invalid.")
                return redirect('form')

            

            form = Form(firstName=firstName, middleName=middleName, lastName=lastName, dob=dob,
                                   gender=gender, motherName=motherName, fatherName=fatherName, aadhaarNumber = aadhaarNumber,
                                   panNumber=panNumber)
            form.save()

            with open('form_details.csv', mode='a', newline='') as file:
                writer = csv.writer(file)

                if file.tell() == 0:
                    writer.writerow(['First Name', 'Middle Name', 'Last Name', 'DOB', 'Gender', 'Mother Name', 'Father Name', 'Aadhaar Number', 'PAN Number'])

                
                writer.writerow([firstName, middleName, lastName, dob_formatted, gender, motherName, fatherName, aadhaarNumber, panNumber])

            messages.info(request, "Registered successfully. Please check your email and verify to activate your account.")
            return redirect('log_in')

    except Exception as e:
            print(e)
            return redirect('form')

    return render(request, "form.html")



def log_in(request):
    try:
        if request.method == "POST":
            username = request.POST.get("username")
            password = request.POST.get("password")

            user_obj = User.objects.filter(username=username).first()
            if user_obj is None:
                messages.info(request, "User not found")
                return redirect('log_in')
            profile_obj = Profile.objects.filter(user = user_obj).first()
            if not profile_obj.is_verified:
                messages.info(request, "Your account has not been verified. Please check your mail to activate your account.")
                return redirect('log_in')
            user = authenticate(username=username, password=password)
            if user is None:
                messages.info(request, "You've entered wrong credentials")
                return redirect('log_in')
        
            login(request, user)
            return redirect('dashboard')
        
    except Exception as e:
        print(e)
        messages.info(request, "Sorry, there's was some error on our side. Please try again later.")
        return redirect('log_in')
    
    return render(request, "log_in.html")
    

def forgot(request):
    try:
        if request.method == "POST":
            email = request.POST.get("email")
            if User.objects.filter(email=email).first():
                user_obj = User.objects.get(email=email)
                forgot_token = str(uuid.uuid4())
                profile_obj = Profile.objects.get(user = user_obj)
                profile_obj.forgot_password_token = forgot_token
                profile_obj.save()
                forgot_password_mail(user_obj.email, forgot_token)
                messages.info(request, "If your email is registered with us, you will receive an email to reset your password.")
                return redirect('forgot')
            else:
                messages.info(request, "Email does not exist")
                return redirect("forgot")               
    except Exception as e:
        print(e)
        return redirect('forgot')
    return render(request, 'forgot.html')



def reset(request, forgot_token):
    profile_obj = Profile.objects.filter(forgot_password_token=forgot_token).first()
    context = {'username': profile_obj}
    try:
        if request.method == "POST":
            newpass = request.POST.get("newpassword")
            conpass = request.POST.get("conpassword")
            username = request.POST.get("username")
            
            
            user_obj = User.objects.filter(username=username).first()
            

            if username is None:
                messages.info(request, "Account does not exist")
                return redirect(f'/reset/{forgot_token}')
            if not is_strong_password(newpass):
                messages.error(request, "Enter a strong password")
                return redirect(f'/reset/{forgot_token}')
            if newpass != conpass:
                messages.info(request, "Passwords don't match")
                return redirect(f'/reset/{forgot_token}')
            
        
            
            user_obj.set_password(newpass)
            user_obj.save()
            messages.success(request, "Password reset successfully. Please log in.")
            return redirect('log_in')
    except User.DoesNotExist:
        messages.info(request, "User does not exist")
        return redirect(reverse('reset', args=[forgot_token]))
        
    return render(request, 'reset.html', context)

@login_required
def dashboard(request):
    uploaded_files = Document.objects.filter(uploaded_by=request.user)
    if Document.is_verified:
            checkbox_data = True
            context = {'uploaded_files': uploaded_files, 'checkbox_data': checkbox_data}
            return render(request, 'dashboard.html', context)
    

@login_required
def upload(request):
    try:
        if request.method == 'POST':
            form = UploadFileForm(request.POST, request.FILES)
            title = request.POST.get('title')
            uploaded_file = request.FILES['file']
            if not uploaded_file.content_type.startswith('image/'):
                messages.error(request, "This file type is not supported.")
                return redirect('upload')
            output = pytesseract.image_to_string(Image.open(uploaded_file))
            tesseract_output = Upload.objects.create(tesseract_output=output, title=title, date=datetime.today())
            
            existing_document = Document.objects.filter(
                title=title,
                uploaded_by=request.user,
                is_verified=True
            ).exists()
            
            if existing_document:
                messages.error(request, "You have already uploaded a verified document with the same title.")
                return redirect('upload')

            filename = "form_details.csv"
            output_strings = output.lower().split()
            chunk_size = 2000

            with open(filename, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for chunk in iter(lambda: list(islice(reader, chunk_size)), []):
                    for row in chunk:
                        if title == "Pan Card":
                            for row in chunk:
                                first_name = row['First Name'].strip().lower()  
                                last_name = row['Last Name'].strip().lower()
                                middle_name = row['Middle Name'].strip().lower()
                                pan = row['PAN Number'].strip().lower()
                                dob = row['DOB'].strip()
                                for j in output_strings:
                                    if (first_name and middle_name and last_name and dob and pan in j.strip()): 
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True  
                                            file.save()
                                            messages.info(request, "Your Document has been verified.")
                                            return redirect('upload')
                            
                            messages.info(request, "Your document has not been verified. Please upload a valid document or review its clarity.")
                            return redirect('upload')
                        elif title == "Aadhar Card":
                            for row in chunk:
                                first_name = row['First Name'].strip().lower()  
                                last_name = row['Last Name'].strip().lower()
                                middle_name = row['Middle Name'].strip().lower()
                                aadhar = row['Aadhaar Number'].strip()
                                dec_aadhar = deconcatenate_aadhar_number(aadhar)
                                dec_aadhar = dec_aadhar.split()
                                dob = row['DOB'].strip()
                            
                                for j in output_strings:
                                    if any(first_name and middle_name and last_name and dob and part in j.strip() for part in dec_aadhar):
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True  
                                            file.save()
                                            messages.info(request, "Your Document has been verified.")
                                            return redirect('upload')
            
                            messages.info(request, "Your document has not been verified. Please upload a valid document or review its clarity.")
                            return redirect('upload')
                            

                        elif title == "CBSE 10th Marksheet":
                            for row in chunk:
                                first_name = row['First Name'].strip().lower()  
                                last_name = row['Last Name'].strip().lower()
                                heading1 = "Central Board of Secondary Education".lower()
                                heading2 = "Secondary School Examination".lower()
                                father_name = row["Father Name"].strip().lower()
                                dob = row['DOB'].strip()
                            
                                for j in output_strings:
                                    if (first_name and father_name and last_name and dob and heading1 and heading2 in j.strip()):
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True  
                                            file.save()
                                            messages.info(request, "Your Document has been verified.")
                                            return redirect('upload')
            
                            
                            messages.info(request, "Your document has not been verified. Please upload a valid document or review its clarity.")
                            return redirect('upload')
                    
                        elif title == "CBSE 12th Marksheet":
                            for row in chunk:
                                first_name = row['First Name'].strip().lower()  
                                last_name = row['Last Name'].strip().lower()
                                heading1 = "Central Board of Secondary Education".lower()
                                heading2 = "Senior School Certificate Examination".lower()
                                father_name = row["Father Name"].strip().lower()
                                mother_name = row["Mother Name"].strip().lower()
                                dob = row['DOB'].strip()

                                for j in output_strings:
                                    if (first_name and father_name and last_name and dob and heading1 and heading2 in j.strip()):
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True  
                                            file.save()
                                            messages.info(request, "Your Document has been verified.")
                                            return redirect('upload')
            
                            
                            messages.info(request, "Your document has not been verified. Please upload a valid document or review its clarity.")
                            return redirect('upload')
                    
                        elif title == "SSC 10th Marksheet":
                            for row in chunk:
                                first_name = row['First Name'].strip().lower()  
                                last_name = row['Last Name'].strip().lower()
                                heading1 = "Secondary School Certificate Examination".lower()
                                heading2 = "Statement of Marks"
                                mother_name = row["Mother Name"].strip().lower()
                            
                                for j in output_strings:
                                    if (first_name and last_name and heading1 and heading2 and mother_name in j.strip()):
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True  
                                            file.save()
                                            messages.info(request, "Your Document has been verified.")
                                            return redirect('upload')
            
                            
                            messages.info(request, "Your document has not been verified. Please upload a valid document or review its clarity.")
                            return redirect('upload')
                    
                        elif title == "HSC 12th Marksheet":
                            for row in chunk:
                                first_name = row['First Name'].strip().lower()  
                                last_name = row['Last Name'].strip().lower()
                                heading1 = "Higher Secondary Certificate Examination".lower()
                                heading2 = "Statement of Marks"
                                mother_name = row["Mother Name"].strip().lower()
                            
                                for j in output_strings:
                                        if (first_name and last_name and heading1 and heading2 and mother_name in j.strip()):
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True  
                                            file.save()
                                            messages.info(request, "Your Document has been verified.")
                                            return redirect('upload')
            
                            
                            messages.info(request, "Your document has not been verified. Please upload a valid document or review its clarity.")
                            return redirect('upload')
                    
                        else:
                            form = UploadFileForm()
    except Exception as e:
        print(e)
        return redirect("upload")
    return render(request, "upload.html")



@login_required
def account(request):
    user = request.user
    context = {'user': user}
    return render(request, 'account.html', context)


def log_out(request):
    try:
        logout(request)
        return redirect('log_in')
    except Exception as e:
        print(e)
        messages.info(request, "Sorry, there's was some error on our side. Please try again later.")
        return redirect("logout")


def about(request):
    return render(request, "about.html")

def contact(request):
    try:
        if request.method == "POST":
            name = request.POST.get('name')
            email = request.POST.get('email')
            desc = request.POST.get('desc')
            contact = Contact(name=name, email=email, desc = desc, date = datetime.today())
            contact.save()
            return redirect("contact")
    except Exception as e:
        print(e)
        return redirect('contact')
    return render(request, "contact.html")



















#Helpers
def send_mail_after_registration(email, token):
    subject = "Your account needs to be verified"
    message = f'Hi paste the link to verify your account http://127.0.0.1:8000/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

def load_csv(filename):
    data = {}
    with open(filename, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            name = row['Full Name']
            data[name] = row
    return data

def is_strong_password(password):
    return len(password) >= 8 and any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password)

def verify(request, auth_token):
    try:
        profile_obj = Profile.objects.filter(auth_token = auth_token).first()
        if profile_obj:
            if profile_obj.is_verified:
                messages.info(request, 'Your account is already verified')
                return redirect('/log_in')
            profile_obj.is_verified = True
            profile_obj.save()
            messages.info(request, "Your account has been verified")
            return redirect('/log_in')
        else:
            return redirect('register')
    except Exception as e:
        print(e)
        return redirect('register')

def forgot_password_mail(email, token):
    subject = "Your Forgot Password link"
    message = f'Click on this link to reset your password http://127.0.0.1:8000/reset/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

def deconcatenate_aadhar_number(number):
    return ' '.join([number[i:i+4] for i in range(0, len(number), 4)])

def single_word(name):
    if name.isalpha() and ' ' not in name:
        return True
    else:
        return False

def is_digit(contact):
    if contact.isdigit():
        return True
    else:
        return False
    
def validate_aadhaar_number(aadhaar_number):
    pattern = r'^[2-9][0-9]{3}[0-9]{4}[0-9]{4}$'
    if re.match(pattern, aadhaar_number):
        return True
    else:
        return False
    
def validate_pan_number(pan_number, last_name):
    pattern = r'^[A-Z]{4}' + last_name[0] + r'[0-9]{4}[A-Z]$'

    if re.match(pattern, pan_number):
        return True
    else:
        return False