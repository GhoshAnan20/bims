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
from PIL import Image, ImageDraw, ImageFont
import io
import csv
from itertools import islice
import re
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import requests
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User, Profile
from .models import Document
import uuid
import base64
from django.http import HttpResponseRedirect
from django.urls import reverse
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode
import secrets
import hashlib
from hashlib import sha256
import os
import cv2
import numpy as np
from django.core.files import File
from django.http import HttpResponseBadRequest
from django.contrib import messages
from django.core.files.base import ContentFile
from django.contrib.auth.decorators import login_required



# watermark function
def add_watermark(input_image, watermark_text, font_path):
    image = Image.open(input_image)
    watermark = Image.new("RGBA", image.size)
    draw = ImageDraw.Draw(watermark, "RGBA")

    width, height = image.size
    font_size = int(min(width, height) / 20)
    
    try:
        font = ImageFont.truetype(font_path, font_size)
    except IOError:
        font = ImageFont.load_default()
    
    # Calculate the text size using textbbox
    text_bbox = draw.textbbox((0, 0), watermark_text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]

    x = width - text_width - 10
    y = height - text_height - 10

    draw.text((x, y), watermark_text, font=font, fill=(255, 255, 255, 128))
    watermarked_image = Image.alpha_composite(image.convert("RGBA"), watermark)
    
    output = io.BytesIO()
    watermarked_image.save(output, format='PNG')
    output.seek(0)

    return output

#document hash
def generate_document_hash():
    random_data = secrets.token_bytes(32)  # Generate 32 bytes of random data
    document_hash = hashlib.sha256(random_data).hexdigest()  # Calculate SHA-256 hash
    return document_hash


#AES Encryption
def encrypt_data(data, password):
    # Generate a random IV
    iv = os.urandom(16)

    # Derive a key from the password using PBKDF2
    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key length
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    # Initialize AES cipher in CBC mode with the derived key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the data using PKCS7 padding
    padder = PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Concatenate the IV with the encrypted data for storage
    encrypted_iv = iv + encrypted_data

    # Return the base64 encoded encrypted IV + data
    return urlsafe_b64encode(encrypted_iv).decode()


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

            # Encrypt sensitive data using AES
            key = 'FrvL2QD*o48Rd*B4Gy6Yz$JzC4r6q#iU'  
            encrypted_username = encrypt_data(username, key)
            encrypted_firstname = encrypt_data(firstname, key)
            encrypted_lastname = encrypt_data(lastname, key)
            encrypted_email = encrypt_data(email, key)
            encrypted_password = encrypt_data(password, key)
            
            myuser = User.objects.create_user(username, email, password)
            myuser.first_name = firstname
            myuser.last_name = lastname
            myuser.save()
            auth_token = str(uuid.uuid4())
            profile_obj = Profile.objects.create(user=myuser, auth_token=auth_token)
            profile_obj.save()
            send_mail_after_registration(email, auth_token)
            
            #json payload
            payload = {
                "username": encrypted_username,
                "firstname": encrypted_firstname,
                "lastname": encrypted_lastname,
                "email": encrypted_email
            }
            
            #api integration
            registration_url = "https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0sgj56b6f/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"
           
            #authentication creds
            username = "e0k62anywl"
            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

            # Encode the credentials in base64 format for Basic Authentication
            credentials = f"{username}:{password}"
            credentials_b64 = base64.b64encode(credentials.encode()).decode()

            # Set up the request headers with Authorization and Content-Type
            headers = {
                "Authorization": f"Basic {credentials_b64}",
                "Content-Type": "application/json"
            }

            # Make the API request
            response = requests.post(registration_url, headers=headers, json=payload)

            if response.status_code == 200:
                # Registration successful
                return redirect("form")
            else:
                # Registration failed
                messages.error(request, "Failed to register user with external service")
                return redirect("form")
                #return HttpResponseRedirect(reverse('register') + f'?error=external-service')

    except Exception as e:
        print(e)
        #messages.error(request, "Sorry! We encountered some error. Please try again later.")

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

            # Encrypt user data using AES
            key = 'UpxXR#HH3N*XDrw3%ymV5op3$b*VdqN$'  # Replace with your secret key
            encrypted_firstName = encrypt_data(firstName, key)
            encrypted_lastName = encrypt_data(lastName, key)
            encrypted_dob = encrypt_data(dob, key)
            encrypted_gender = encrypt_data(gender, key)
            encrypted_motherName = encrypt_data(motherName, key)
            encrypted_fatherName = encrypt_data(fatherName, key)
            encrypted_aadhaarNumber = encrypt_data(aadhaarNumber, key)
            encrypted_panNumber = encrypt_data(panNumber, key)

            # Prepare JSON payload with encrypted data
            payload = {
                "encrypted_firstName": encrypted_firstName,
                "encrypted_lastName": encrypted_lastName,
                "encrypted_dob": encrypted_dob,
                "encrypted_gender": encrypted_gender,
                "encrypted_motherName": encrypted_motherName,
                "encrypted_fatherName": encrypted_fatherName,
                "encrypted_aadhaarNumber": encrypted_aadhaarNumber,
                "encrypted_panNumber": encrypted_panNumber
            }

            # Define the endpoint URL of your backend server
            url = "https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0hld8j8ov/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"

            #authentication creds
            username = "e0k62anywl"
            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

            # Encode the credentials in base64 format for Basic Authentication
            credentials = f"{username}:{password}"
            credentials_b64 = base64.b64encode(credentials.encode()).decode()

            # Set up the request headers with Authorization and Content-Type
            headers = {
                "Authorization": f"Basic {credentials_b64}",
                "Content-Type": "application/json"
            }

            # Send POST request to your backend server
            response = requests.post(url, json=payload)

            if response.status_code == 200:
                # Data submitted successfully to the smart contract
                messages.info(request, "Data submitted successfully to the smart contract.")
                return redirect('log_in')
            else:
                # Handle error response from backend server
                messages.error(request, "Failed to submit data to the smart contract.")
                return redirect('form')

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

'''
@login_required
def dashboard(request):
    uploaded_files = Document.objects.filter(uploaded_by=request.user)
    if Document.is_verified:
            checkbox_data = True
            context = {'uploaded_files': uploaded_files, 'checkbox_data': checkbox_data}
            return render(request, 'dashboard.html', context)
'''
@login_required
def dashboard(request):
    uploaded_files = Document.objects.filter(uploaded_by=request.user, is_verified=True)
    checkbox_data = any(file.is_verified for file in uploaded_files)
    context = {'uploaded_files': uploaded_files, 'checkbox_data': checkbox_data}
    return render(request, 'dashboard.html', context)


@login_required
def upload(request):
    try:
        if request.method == 'POST':
            form = UploadFileForm(request.POST, request.FILES)
            title = request.POST.get('title')
            uploaded_file = request.FILES.get('file')
            if not uploaded_file.content_type.startswith('image/'):
                messages.error(request, "This file type is not supported.")
                return redirect('upload')

            output = pytesseract.image_to_string(Image.open(uploaded_file))
            tesseract_output = Upload.objects.create(tesseract_output=output, title=title, date=datetime.today())
            is_verified = True
            existing_document = Document.objects.filter(
                title=title,
                uploaded_by=request.user,
                is_verified=is_verified
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
                                            date=datetime.now(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True


                                            document_hash = uuid.uuid4().hex
                                            print(document_hash)
                                            timestamp = int(datetime.now().timestamp())
                                            
                                            payload = {
                                                "documentHash": document_hash,
                                                "isVerified": True,  # Assuming verification is successful
                                                "timestamp": timestamp  # Include the timestamp in the payload
                                            }
                                            json_payload = json.dumps(payload)

                                            # Smart contract integration
                                            verification_url = f"https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0hwi955ix/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"

                                            #authentication creds
                                            username = "e0k62anywl"
                                            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

                                            #encode credentials
                                            credentials = f"{username}:{password}"
                                            credentials_b64 = base64.b64encode(credentials.encode()).decode()

                                            #headers
                                            headers = { "Authorization": f"Basic {credentials_b64}",
                                                       "Content-Type": "application/json"
                                                    }

                                            # Make the API request to submit verification to the smart contract
                                            response = requests.post(verification_url, headers=headers, json=payload)

                                            #response log
                                            print(f"Response Status Code: {response.status_code}")
                                            print(f"Response Content: {response.content}")

                                            if response.status_code == 200:
                                                response_data = response.json()
                                                transaction_id = response_data.get('transactionHash')
                                                print(f"Transaction ID: {transaction_id}")
                                                
                                                #watermark
                                                font_path = "/home/ubuntu/bims/fonts/Roboto-Regular.ttf"
                                                watermarked_image = add_watermark(uploaded_file, transaction_id, font_path)

                                                #save watermark file only
                                                watermarked_file = ContentFile(watermarked_image.read())
                                                watermarked_file.name = f"{uploaded_file.name.split('.')[0]}_watermarked.png"
                                                Document.objects.filter(file=uploaded_file, uploaded_by=request.user).delete()


                                                # Verification successful
                                                file = Document.objects.create(
                                                    title=title,
                                                    file=watermarked_file,
                                                    date=datetime.today(),
                                                    uploaded_by=request.user,
                                                    is_verified=True,
                                                    transaction_id=transaction_id
                                                )
                                                #file.is_verified = True
                                                #file.document_hash = document_hash  # Store the document hash in the database
                                                file.transaction_id = transaction_id
                                                file.file.save(f"uploaded_file.name.split('.')[0]_watermarked.png", watermarked_image)
                                                file.save()
                                                

                                                messages.info(request, "Your Document has been verified.")
                                                return redirect('upload')
                                            else:
                                                # Verification failed
                                                messages.error(request, "Failed to verify document. Please try again.")
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
                                            document_hash = uuid.uuid4().hex
                                            print(document_hash)
                                            timestamp = int(datetime.now().timestamp())
                                            
                                            
                                            payload = {
                                                "documentHash": document_hash,
                                                "isVerified": True,  # Assuming verification is successful
                                                "timestamp": timestamp  # Include the timestamp in the payload
                                            }
                                            json_payload = json.dumps(payload)

                                            # Smart contract integration
                                            verification_url = f"https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0hwi955ix/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"

                                            #authentication creds
                                            username = "e0k62anywl"
                                            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

                                            #encode credentials
                                            credentials = f"{username}:{password}"
                                            credentials_b64 = base64.b64encode(credentials.encode()).decode()

                                            #headers
                                            headers = { "Authorization": f"Basic {credentials_b64}",
                                                       "Content-Type": "application/json"
                                                    }

                                            # Make the API request to submit verification to the smart contract
                                            response = requests.post(verification_url, headers=headers, json=payload)

                                            #response log
                                            print(f"Response Status Code: {response.status_code}")
                                            print(f"Response Content: {response.content}")

                                            if response.status_code == 200:
                                                response_data = response.json()
                                                transaction_id = response_data.get('transactionHash')
                                                print(f"Transaction ID: {transaction_id}")
                                                
                                                #watermark
                                                font_path = "/home/ubuntu/bims/fonts/Roboto-Regular.ttf"
                                                watermarked_image = add_watermark(uploaded_file, transaction_id, font_path)

                                                # Verification successful
                                                file = Document.objects.create(
                                                    title=title,
                                                    file=uploaded_file,
                                                    date=datetime.today(),
                                                    uploaded_by=request.user
                                                )
                                                file.is_verified = True
                                                file.document_hash = document_hash  # Store the document hash in the database
                                                file.transaction_id = transaction_id
                                                file.file.save(f"uploaded_file.name.split('.')[0]_watermarked.png", watermarked_image)
                                                file.save()
                                                

                                                messages.info(request, "Your Document has been verified.")
                                                return redirect('upload')
                                            else:
                                                # Verification failed
                                                messages.error(request, "Failed to verify document. Please try again.")
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
                                    if (first_name and father_name and last_name and heading1 and heading2 in j.strip()):
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            file.is_verified = True  
                                            document_hash = uuid.uuid4().hex
                                            print(document_hash)
                                            timestamp = int(datetime.now().timestamp())
                                            
                                            payload = {
                                                "documentHash": document_hash,
                                                "isVerified": True,  # Assuming verification is successful
                                                "timestamp": timestamp  # Include the timestamp in the payload
                                            }
                                            json_payload = json.dumps(payload)

                                            # Smart contract integration
                                            verification_url = f"https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0hwi955ix/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"

                                            #authentication creds
                                            username = "e0k62anywl"
                                            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

                                            #encode credentials
                                            credentials = f"{username}:{password}"
                                            credentials_b64 = base64.b64encode(credentials.encode()).decode()

                                            #headers
                                            headers = { "Authorization": f"Basic {credentials_b64}",
                                                       "Content-Type": "application/json"
                                                    }

                                            # Make the API request to submit verification to the smart contract
                                            response = requests.post(verification_url, headers=headers, json=payload)

                                            #response log
                                            print(f"Response Status Code: {response.status_code}")
                                            print(f"Response Content: {response.content}")

                                            if response.status_code == 200:
                                                response_data = response.json()
                                                transaction_id = response_data.get('transactionHash')
                                                print(f"Transaction ID: {transaction_id}")
                                                
                                                #watermark
                                                font_path = "/home/ubuntu/bims/fonts/Roboto-Regular.ttf"
                                                watermarked_image = add_watermark(uploaded_file, transaction_id, font_path)

                                                # Verification successful
                                                file = Document.objects.create(
                                                    title=title,
                                                    file=uploaded_file,
                                                    date=datetime.today(),
                                                    uploaded_by=request.user
                                                )
                                                file.is_verified = True
                                                file.document_hash = document_hash  # Store the document hash in the database
                                                file.transaction_id = transaction_id
                                                file.file.save(f"uploaded_file.name.split('.')[0]_watermarked.png", watermarked_image)
                                                file.save()
                                                

                                                messages.info(request, "Your Document has been verified.")
                                                return redirect('upload')
                                            else:
                                                # Verification failed
                                                messages.error(request, "Failed to verify document. Please try again.")
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
                                    if (first_name and father_name and last_name and heading1 and heading2 in j.strip()):
                                            file, created = Document.objects.get_or_create(
                                            title= title,  
                                            file= uploaded_file,  
                                            date=datetime.today(),
                                            uploaded_by = request.user
                                )
                                            document_hash = uuid.uuid4().hex
                                            print(document_hash)
                                            timestamp = int(datetime.now().timestamp())
                                            
                                            payload = {
                                                "documentHash": document_hash,
                                                "isVerified": True,  # Assuming verification is successful
                                                "timestamp": timestamp  # Include the timestamp in the payload
                                            }
                                            json_payload = json.dumps(payload)

                                            # Smart contract integration
                                            verification_url = f"https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0hwi955ix/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"

                                            #authentication creds
                                            username = "e0k62anywl"
                                            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

                                            #encode credentials
                                            credentials = f"{username}:{password}"
                                            credentials_b64 = base64.b64encode(credentials.encode()).decode()

                                            #headers
                                            headers = { "Authorization": f"Basic {credentials_b64}",
                                                       "Content-Type": "application/json"
                                                    }

                                            # Make the API request to submit verification to the smart contract
                                            response = requests.post(verification_url, headers=headers, json=payload)

                                            #response log
                                            print(f"Response Status Code: {response.status_code}")
                                            print(f"Response Content: {response.content}")

                                            if response.status_code == 200:
                                                response_data = response.json()
                                                transaction_id = response_data.get('transactionHash')
                                                print(f"Transaction ID: {transaction_id}")
                                                
                                                #watermark
                                                font_path = "/home/ubuntu/bims/fonts/Roboto-Regular.ttf"
                                                watermarked_image = add_watermark(uploaded_file, transaction_id, font_path)

                                                # Verification successful
                                                file = Document.objects.create(
                                                    title=title,
                                                    file=uploaded_file,
                                                    date=datetime.today(),
                                                    uploaded_by=request.user
                                                )
                                                file.is_verified = True
                                                file.document_hash = document_hash  # Store the document hash in the database
                                                file.transaction_id = transaction_id
                                                file.file.save(f"uploaded_file.name.split('.')[0]_watermarked.png", watermarked_image)
                                                file.save()
                                                

                                                messages.info(request, "Your Document has been verified.")
                                                return redirect('upload')
                                            else:
                                                # Verification failed
                                                messages.error(request, "Failed to verify document. Please try again.")
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
                                            document_hash = uuid.uuid4().hex
                                            print(document_hash)
                                            timestamp = int(datetime.now().timestamp())
                                            
                                            payload = {
                                                "documentHash": document_hash,
                                                "isVerified": True,  # Assuming verification is successful
                                                "timestamp": timestamp  # Include the timestamp in the payload
                                            }
                                            json_payload = json.dumps(payload)

                                            # Smart contract integration
                                            verification_url = f"https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0hwi955ix/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"

                                            #authentication creds
                                            username = "e0k62anywl"
                                            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

                                            #encode credentials
                                            credentials = f"{username}:{password}"
                                            credentials_b64 = base64.b64encode(credentials.encode()).decode()

                                            #headers
                                            headers = { "Authorization": f"Basic {credentials_b64}",
                                                       "Content-Type": "application/json"
                                                    }

                                            # Make the API request to submit verification to the smart contract
                                            response = requests.post(verification_url, headers=headers, json=payload)

                                            #response log
                                            print(f"Response Status Code: {response.status_code}")
                                            print(f"Response Content: {response.content}")

                                            if response.status_code == 200:
                                                response_data = response.json()
                                                transaction_id = response_data.get('transactionHash')
                                                print(f"Transaction ID: {transaction_id}")
                                                
                                                #watermark
                                                font_path = "/home/ubuntu/bims/fonts/Roboto-Regular.ttf"
                                                watermarked_image = add_watermark(uploaded_file, transaction_id, font_path)

                                                watermarked_file = ContentFile(watermarked_image.read())
                                                watermarked_file.name = f"{uploaded_file.name.split('.')[0]}_watermarked.png"
                                                Document.objects.filter(file=uploaded_file, uploaded_by=request.user).delete()

                                                # Verification successful
                                                file = Document.objects.create(
                                                    title=title,
                                                    date=datetime.today(),
                                                    is_verified=True,
                                                    file=watermarked_file,
                                                    uploaded_by=request.user
                                                )
                                                file.is_verified = True
                                                file.document_hash = document_hash  # Store the document hash in the database
                                                file.transaction_id = transaction_id
                                                file.file.save(f"uploaded_file.name.split('.')[0]_watermarked.png", watermarked_image)
                                                file.save()
                                                

                                                messages.info(request, "Your Document has been verified.")
                                                return redirect('upload')
                                            else:
                                                # Verification failed
                                                messages.error(request, "Failed to verify document. Please try again.")
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
                                            document_hash = uuid.uuid4().hex
                                            print(document_hash)
                                            timestamp = int(datetime.now().timestamp())
                                            
                                            payload = {
                                                "documentHash": document_hash,
                                                "isVerified": True,  # Assuming verification is successful
                                                "timestamp": timestamp  # Include the timestamp in the payload
                                            }
                                            json_payload = json.dumps(payload)

                                            # Smart contract integration
                                            verification_url = f"https://e0bfric3h9-e0gc9utcak-connect.de0-aws.kaleido.io/gateways/e0hwi955ix/?kld-from=0xc916d7e0731fd8951c81981217c6a863796857b4&kld-sync=true"

                                            #authentication creds
                                            username = "e0k62anywl"
                                            password = "Mm5qhsv5QUEIFQiaEChHrva3_P_febOQLGM6HDhrT3o"

                                            #encode credentials
                                            credentials = f"{username}:{password}"
                                            credentials_b64 = base64.b64encode(credentials.encode()).decode()

                                            #headers
                                            headers = { "Authorization": f"Basic {credentials_b64}",
                                                       "Content-Type": "application/json"
                                                    }

                                            # Make the API request to submit verification to the smart contract
                                            response = requests.post(verification_url, headers=headers, json=payload)

                                            #response log
                                            print(f"Response Status Code: {response.status_code}")
                                            print(f"Response Content: {response.content}")

                                            if response.status_code == 200:
                                                response_data = response.json()
                                                transaction_id = response_data.get('transactionHash')
                                                print(f"Transaction ID: {transaction_id}")
                                                
                                                #watermark
                                                font_path = "/home/ubuntu/bims/fonts/Roboto-Regular.ttf"
                                                watermarked_image = add_watermark(uploaded_file, transaction_id, font_path)

                                                # Verification successful
                                                file = Document.objects.create(
                                                    title=title,
                                                    file=uploaded_file,
                                                    date=datetime.today(),
                                                    uploaded_by=request.user
                                                )
                                                file.is_verified = True
                                                file.document_hash = document_hash  # Store the document hash in the database
                                                file.transaction_id = transaction_id
                                                file.file.save(f"uploaded_file.name.split('.')[0]_watermarked.png", watermarked_image)
                                                file.save()
                                                

                                                messages.info(request, "Your Document has been verified.")
                                                return redirect('upload')
                                            else:
                                                # Verification failed
                                                messages.error(request, "Failed to verify document. Please try again.")
                                                return redirect('upload')
                    
                        else:
                            form = UploadFileForm()
    except Exception as e:
        print(e)
        return redirect("upload")
    return render(request, "upload.html")


'''
@login_required
def account(request):
    user = request.user
    context = {'user': user}
    transactions = Document.objects.filter(uploaded_by=user, is_verified=True).values('date','title','transaction_id')
    print("Transactions:", transactions)
    content={
            'user': user,
            'transactions': transactions
            }
    return render(request, 'account.html', context)
'''

from django.shortcuts import render
from django.contrib.auth.decorators import login_required  # Import the login_required decorator if not already imported
from django.contrib.auth.models import User
from bimsapp.models import Document

@login_required
def account(request):
    user = request.user
    transactions = Document.objects.filter(uploaded_by=user, is_verified=True)
    context = {'user': user, 'transactions': transactions}  # Pass the transactions queryset to the template context
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
    message = f'Hi paste the link to verify your account http://15.206.15.216:8000/verify/{token}'
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
            messages.info(request, "hey")
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
