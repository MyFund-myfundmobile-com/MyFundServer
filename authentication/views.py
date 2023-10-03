from rest_framework import status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework.decorators import (
    api_view, authentication_classes, permission_classes, api_view, 
    permission_classes, parser_classes
)
from rest_framework.permissions import (
    IsAuthenticated, AllowAny
)
from .serializers import (
    SignupSerializer, ConfirmOTPSerializer, UserSerializer
)
import random
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from rest_framework.views import APIView
from django.contrib.auth import logout
from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from authentication.models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserProfileUpdateSerializer
from rest_framework.permissions import IsAuthenticated
from .serializers import ProfilePictureUpdateSerializer
from rest_framework.parsers import FileUploadParser
from datetime import datetime
from django.utils.safestring import mark_safe



@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def signup(request):
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()

        # Generate OTP (you can use your own logic here)
        otp = generate_otp()
        user.otp = otp
        user.save()

        # Send OTP to user's email
        send_otp_email(user, otp)

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# @api_view(['POST'])
# @permission_classes([AllowAny])
# @csrf_exempt
# def confirm_otp(request):
#     serializer = ConfirmOTPSerializer(data=request.data)
#     if serializer.is_valid():
#         otp = serializer.validated_data['otp']

#         try:
#             user = CustomUser.objects.get(otp=otp)
#             if user.is_active:
#                 return Response({'message': 'Account already confirmed.'}, status=status.HTTP_400_BAD_REQUEST)
            
#             user.is_active = True
#             user.save()
#             print("Account confirmed successfully.")
#             return Response({'message': 'Account confirmed successfully.'}, status=status.HTTP_200_OK)
#         except CustomUser.DoesNotExist:
#             print("Invalid OTP.")
#             return Response({'message': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




def generate_otp():
    return ''.join(random.choices('0123456789', k=6))

def send_otp_email(user, otp):
    subject = "[OTP] Did you just signup?"

    current_year = datetime.now().year  # Get the current year

    logo_url = "https://drive.google.com/uc?export=view&id=1MorbW_xLg4k2txNQdhUnBVxad8xeni-N"

    message = f"""
    <p><img src="{logo_url}" alt="MyFund Logo" style="display: block; margin: 0 auto; max-width: 100px; height: auto;"></p>

    <p>Hi {user.first_name}, </p>

    <p>We heard you'd like a shiny new MyFund account. Use the One-Time-Password (OTP) below to complete your signup. This code is valid only for 20 minutes, so chop-chop!</p>

    <h1 style="text-align: center; font-size: 24px;">{otp}</h1>

    <p>If you did not request to create a MyFund account, kindly ignore this email. Otherwise, buckle up, you're in for a treat!</p>

    <p>Cheers!<br>Your friends at MyFund</p>

    
    ...
    <p>Save, Buy Properties, Earn Rent<br>
    13, Gbajabiamila Street, Ayobo, Lagos.<br>
    www.myfundmobile.com</p>

    <p>MyFund ©{current_year}</p>


    """

    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    send_mail(subject, mark_safe(message), from_email, recipient_list, html_message=mark_safe(message))









@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def confirm_otp(request):
    serializer = ConfirmOTPSerializer(data=request.data)
    if serializer.is_valid():
        otp = serializer.validated_data['otp']

        try:
            user = CustomUser.objects.get(otp=otp, is_confirmed=False)  # Only confirm if not already confirmed
            user.is_confirmed = True
            user.save()
            return Response({'message': 'Account confirmed successfully.'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'message': 'Invalid OTP or account already confirmed.'}, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





def test_email(request):
    send_mail(
        'Test Email',
        'This is a test email body.',
        'myfundmobile@gmail.com',
        ['valueplusrecords@gmail.com'],
        fail_silently=False,
    )
    return HttpResponse("Test email sent. This shows the email system is working")



class CustomObtainAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_id': user.id,
        })


from rest_framework.permissions import AllowAny

class LogoutView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this endpoint

    def post(self, request):
        logout(request)
        return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)



class OTPVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        received_otp = request.data.get('otp')
        user = request.user  # Assuming the user is authenticated

        if user.otp == received_otp and not user.otp_verified:
            # OTP matches and is not yet verified
            user.otp_verified = True
            user.save()
            return Response({'success': True})
        else:
            return Response({'success': False})






@api_view(['POST'])
@csrf_exempt
def request_password_reset(request):
    if request.method == 'POST':
        email = request.data.get('email')

        try:
            user = CustomUser.objects.get(email=email)
            user.generate_reset_token()
            user.send_password_reset_email()
            
            return Response({'detail': 'Password reset email sent successfully.'})
        except ObjectDoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    return Response({'detail': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@csrf_exempt
def reset_password(request):
    if request.method == 'POST':
        token = request.GET.get('token')  # Get the token from URL parameters
        password = request.data.get('password')  # Retrieve from request data
        confirm_password = request.data.get('confirm_password')  # Retrieve from request data
        
        if token:  # Check if token is provided
            try:
                user = CustomUser.objects.get(reset_token=token, reset_token_expires__gte=timezone.now())
                if password == confirm_password:
                    print("Updating password...")
                    user.set_password(password)
                    user.reset_token = None
                    user.reset_token_expires = None
                    user.save()
                    print("Password update completed")
                    return JsonResponse({'message': 'Password reset successful'})
                else:
                    return JsonResponse({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
            except CustomUser.DoesNotExist:
                return JsonResponse({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return JsonResponse({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)
    
    return JsonResponse({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)




@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    print("Headers:", request.headers)
    print("Data:", request.data)
    print("Token:", request.auth)  # Print the token to verify it's being extracted
    
    if request.user.is_authenticated:
        print("Authenticated user:", request.user)
    else:
        print("User not authenticated.")
        
    user = request.user
    profile_data = {
        "firstName": user.first_name,
        "lastName": user.last_name,
        "mobileNumber": user.phone_number,
        "email": user.email,
        "profile_picture": user.profile_picture.url if user.profile_picture else None,
        'preferred_asset': user.preferred_asset,
        'savings_goal_amount': user.savings_goal_amount,
        'time_period': user.time_period,
    }
    return Response(profile_data)

            


@api_view(['PATCH'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_user_profile(request):
    user = request.user
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    phone_number = request.data.get('phone_number')

    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name
    if phone_number:
        user.phone_number = phone_number

    user.save()
    return Response({'message': 'Profile updated successfully.'}, status=status.HTTP_200_OK)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def profile_picture_update(request):
    user = request.user
    serializer = ProfilePictureUpdateSerializer(user, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()
        
        # Get the updated user instance
        updated_user = CustomUser.objects.get(id=user.id)
        
        # Create a dictionary with the updated user information
        updated_user_data = {
            "firstName": updated_user.first_name,
            "lastName": updated_user.last_name,
            "mobileNumber": updated_user.phone_number,
            "email": updated_user.email,
            "profile_picture": updated_user.profile_picture.url,
        }
        
        return Response({'message': 'Profile picture updated successfully.', 'user': updated_user_data})
    
    return Response(serializer.errors, status=400)




from .serializers import SavingsGoalUpdateSerializer
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_savings_goal(request):
    user = request.user

    serializer = SavingsGoalUpdateSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()

        # Set is_first_time_signup flag to False after first login
        if user.is_first_time_signup:
            user.is_first_time_signup = False
            user.save()
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from .serializers import MessageSerializer  # Create a serializer for AdminMessage if needed
from .models import AutoSave, Message
from django.contrib.auth import get_user_model
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from rest_framework.parsers import MultiPartParser

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser])
def send_message(request, recipient_id):
    user = request.user
    content = request.data.get('content')
    image = request.data.get('image')

    recipient_id = 1

    try:
        recipient = get_user_model().objects.get(id=recipient_id)
    except get_user_model().DoesNotExist:
        return Response({'error': 'Recipient not found'}, status=status.HTTP_404_NOT_FOUND)

    if not content and not image:
        return Response({'error': 'Message content or image is required'}, status=status.HTTP_400_BAD_REQUEST)

    message = Message.objects.create(sender=user, recipient=recipient, content=content, image=image)

    message_data = {
        'type': 'chat.message',
        'message': {
            'content': message.content,
            'image': message.image.url if message.image else None,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'sender_id': message.sender.id,
        }
    }

    return Response({'success': True})




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_messages(request, recipient_id):
    user = request.user
    recipient = get_user_model().objects.get(id=recipient_id)

    # Retrieve messages from the database
    messages = Message.objects.filter(sender__in=[user, recipient], recipient__in=[user, recipient]).order_by('timestamp')

    # Serialize messages and create a list of message data
    message_data_list = []
    for message in messages:
        message_data = {
            'content': message.content,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'sender_id': message.sender.id,
            'image': message.image.url if message.image else None,  # Include the image URL if available
        }
        message_data_list.append(message_data)

    return Response(message_data_list)




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_admin_reply(request, message_id):
    admin_user = request.user
    content = request.data.get('content')

    try:
        message = Message.objects.get(id=message_id)
        if message.recipient != admin_user:
            return Response({'error': 'You are not authorized to reply to this message'}, status=status.HTTP_403_FORBIDDEN)

    except Message.DoesNotExist:
        return Response({'error': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)

    if not content:
        return Response({'error': 'Message content is required'}, status=status.HTTP_400_BAD_REQUEST)

    # Create a new message from admin to user
    reply_message = Message.objects.create(sender=admin_user, recipient=message.sender, content=content)

    return Response({'success': True})










from django.contrib import messages
from django.urls import reverse

def reply_to_message(request, message_id):
    # Logic to handle replying to a message
    if request.method == 'POST':
        # Process the reply message and save it to the database
        reply_content = request.POST.get('content')  # Get the reply content from the form
        if reply_content:
            # Process the reply content and save it to the database
            # For example, you can create a new message instance and save it
            
            messages.success(request, 'Reply message sent successfully.')
            return redirect(reverse('admin:authentication_message_changelist'))
        else:
            messages.error(request, 'Reply content cannot be empty.')
            return redirect(reverse('admin:authentication_message_changelist'))
    
    # Render a form to reply to the message
    context = {
        'message_id': message_id,
    }
    return render(request, 'admin/message/reply_message.html', context)




from .serializers import BankAccountSerializer
from .models import BankAccount
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from .serializers import BankAccountSerializer
import requests

class BankAccountViewSet(viewsets.ModelViewSet):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'])
    def get_user_banks(self, request):
        user_banks = BankAccount.objects.filter(user=request.user)
        serializer = BankAccountSerializer(user_banks, many=True)
        return Response(serializer.data)

    def resolve_account(self, account_number, bank_code):
        secret_key = "sk_test_dacd07b029231eed22f407b3da805ecafdf2668f"
        url = f"https://api.paystack.co/bank/resolve?account_number={account_number}&bank_code={bank_code}"
        headers = {"Authorization": f"Bearer {secret_key}"}

        response = requests.get(url, headers=headers)

        if response.status_code == status.HTTP_200_OK:
            response_data = response.json()
            account_name = response_data.get("data", {}).get("account_name", "")
            return account_name
        else:
            return None

    def perform_create(self, serializer):
        account_number = self.request.data.get("account_number")
        bank_code = self.request.data.get("bank_code")

        if account_number and bank_code:
            account_name = self.resolve_account(account_number, bank_code)

            if account_name is not None:
                serializer.save(user=self.request.user, bank_name=account_name, account_number=account_number)
                return Response({"message": "Bank account added successfully."}, status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "Failed to resolve account details."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            serializer.save(user=self.request.user)
            return Response({"message": "Bank account added without account details resolution."}, status=status.HTTP_201_CREATED)



from django.db import IntegrityError

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_bank_account(request):
    account_number = request.data.get("accountNumber")
    bank_name = request.data.get("bankName")
    account_name = request.data.get("accountName")

    if account_number and bank_name and account_name:
        try:
            bank_account = BankAccount(
                user=request.user,
                bank_name=bank_name,
                account_number=account_number,
                account_name=account_name,
                is_default=False
            )
            bank_account.save()

            serializer = BankAccountSerializer(bank_account)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except IntegrityError:
            return Response(
                {"error": "This bank account is already associated with another user."},
                status=status.HTTP_400_BAD_REQUEST
            )

    else:
        return Response(
            {"error": "Account number, bank name, and account name are required."},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    
from django.db.models import Count
from django.db import transaction


@api_view(['DELETE'])
def delete_bank_account(request, account_number):
    try:
        bank_account = BankAccount.objects.get(account_number=account_number)
    except BankAccount.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        duplicates = BankAccount.objects.filter(account_number=account_number).annotate(count=Count('id')).filter(count__gt=1)

        with transaction.atomic():
            for duplicate in duplicates:
                if duplicate.id != bank_account.id:
                    duplicate.delete()

            bank_account.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)
    



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_banks(request):
    user_banks = BankAccount.objects.filter(user=request.user)
    serializer = BankAccountSerializer(user_banks, many=True)
    return Response(serializer.data)




from .models import Card
from .serializers import CardSerializer, TransactionSerializer
from rest_framework import generics


class BankAccountListCreateView(generics.ListCreateAPIView):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class BankAccountDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def perform_destroy(self, instance):
        instance.delete()

class UserBankAccountListView(generics.ListAPIView):
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return BankAccount.objects.filter(user=self.request.user)






class CardListCreateView(generics.ListCreateAPIView):
    queryset = Card.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class CardDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Card.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

class UserCardListView(generics.ListAPIView):
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Card.objects.filter(user=self.request.user)
    
class DeleteCardView(generics.DestroyAPIView):
    queryset = Card.objects.all()
    serializer_class = CardSerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        card = self.get_object()
        card.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)




class TransactionCreateView(generics.CreateAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(
            user=self.request.user,  # Set the user field to the authenticated user
            description="Add Card Transaction"  # Provide a transaction description
        )

from .models import Transaction

channel_layer = get_channel_layer()

# Modify UserTransactionListView to use the Transaction model
class UserTransactionListView(generics.ListAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        transactions = Transaction.objects.filter(user=user).order_by('-date', '-time')
        return transactions



from .serializers import AccountBalancesSerializer

class AccountBalancesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = AccountBalancesSerializer(user)
        return Response(serializer.data)


from graphene_django.views import GraphQLView
from graphql_jwt.decorators import jwt_cookie
from django.utils.decorators import method_decorator

class CustomGraphQLView(GraphQLView):
    @method_decorator(jwt_cookie)
    def dispatch(self, request, *args, **kwargs):
        # Your existing authentication logic
        if request.user.is_authenticated:
            print("User is authenticated:", request.user)
            return super().dispatch(request, *args, **kwargs)
        else:
            print("User is not authenticated. Sending 401 response.")
            return JsonResponse({'error': 'Authentication required. Login first'}, status=401)







@api_view(['POST'])
@permission_classes([IsAuthenticated])
def quicksave(request):
    # Get the selected card details from the request
    card_id = request.data.get('card_id')
    amount = request.data.get('amount')

    # Retrieve the card details from your database
    try:
        card = Card.objects.get(id=card_id)
    except Card.DoesNotExist:
        return Response({'error': 'Selected card not found'}, status=status.HTTP_404_NOT_FOUND)

    # Use the card details to initiate a payment with Paystack
    paystack_secret_key = "sk_test_dacd07b029231eed22f407b3da805ecafdf2668f"  # Use your actual secret key
    paystack_url = "https://api.paystack.co/charge"

    payload = {
        "card": {
            "number": card.card_number,
            "cvv": card.cvv,
            "expiry_month": card.expiry_date.split('/')[0],
            "expiry_year": card.expiry_date.split('/')[1],
        },
        "email": request.user.email,  # Assuming you have a user authenticated with a JWT token
        "amount": int(amount) * 100,  # Amount in kobo (multiply by 100)
    }

    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }

    response = requests.post(paystack_url, json=payload, headers=headers)
    paystack_response = response.json()

    if paystack_response.get("status"):
        # Payment successful, update user's savings and create a transaction
        user = request.user
        user.savings += int(amount)
        user.save()


        # Send a confirmation email
        subject = "QuickSave Successful!"
        message = f"Well done {user.first_name},\n\nYour QuickSave was successful and ₦{amount} has been successfully added to your SAVINGS account. \n\nKeep growing your funds.🥂\n\nMyFund"
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        # Create a transaction record
        transaction = Transaction.objects.create(
            user=user,
            transaction_type="credit",
            amount=int(amount),
            date=timezone.now().date(),
            time=timezone.now().time(),
            description=f"QuickSave",
            transaction_id=paystack_response.get("data", {}).get("reference"),
        )

        # Return a success response
        return Response({'message': 'QuickSave successful', 'transaction_id': transaction.transaction_id}, status=status.HTTP_200_OK)
    else:
        # Payment failed, return an error response
        return Response({'error': 'QuickSave failed'}, status=status.HTTP_400_BAD_REQUEST)



import time
import threading

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def autosave(request):
    user = request.user
    card_id = request.data.get('card_id')
    amount = request.data.get('amount')
    frequency = request.data.get('frequency')

    # Validate frequency (should be one of 'hourly', 'daily', 'weekly', 'monthly')
    valid_frequencies = ['hourly', 'daily', 'weekly', 'monthly']
    if frequency not in valid_frequencies:
        return Response({'error': 'Invalid frequency'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        active_autosave = AutoSave.objects.get(user=user, active=True)
        return Response({'error': 'User already has an active autosave'}, status=status.HTTP_400_BAD_REQUEST)
    except AutoSave.DoesNotExist:
        pass

        card = Card.objects.get(id=card_id)
    except Card.DoesNotExist:
        return Response({'error': 'Selected card not found'}, status=status.HTTP_404_NOT_FOUND)

    # Calculate the interval based on the selected frequency (in seconds)
    intervals = {
        'hourly': 3600,
        'daily': 86400,
        'weekly': 604800,
        'monthly': 2419200,  # Approximation for 28-31 days
    }

    interval_seconds = intervals.get(frequency)

    if not interval_seconds:
        return Response({'error': 'Invalid frequency'}, status=status.HTTP_400_BAD_REQUEST)

    # Create an 'AutoSave' record
    AutoSave.objects.create(user=user, frequency=frequency, amount=amount, active=True)

    # Use the card details to initiate a payment with Paystack periodically
    def auto_charge():
        while True:
            # Delay for the specified interval
            time.sleep(interval_seconds)

            # Perform the auto charge
            paystack_secret_key = "sk_test_dacd07b029231eed22f407b3da805ecafdf2668f"  # Use your actual secret key
            paystack_url = "https://api.paystack.co/charge"

            payload = {
                "card": {
                    "number": card.card_number,
                    "cvv": card.cvv,
                    "expiry_month": card.expiry_date.split('/')[0],
                    "expiry_year": card.expiry_date.split('/')[1],
                },
                "email": user.email,
                "amount": int(amount) * 100,  # Amount in kobo (multiply by 100)
            }

            headers = {
                "Authorization": f"Bearer {paystack_secret_key}",
                "Content-Type": "application/json",
            }

            response = requests.post(paystack_url, json=payload, headers=headers)
            paystack_response = response.json()

            if paystack_response.get("status"):
                # Payment successful, update user's savings and create a transaction
                user.savings += int(amount)
                user.save()

                # Create a transaction record
                Transaction.objects.create(
                    user=user,
                    transaction_type="credit",
                    amount=int(amount),
                    date=timezone.now().date(),
                    time=timezone.now().time(),
                    description=f"AutoSave",
                    transaction_id=paystack_response.get("data", {}).get("reference"),
                )

                # Send a confirmation email
                subject = "AutoSave Successful!"
                message = f"Hi {user.first_name},\n\nYour AutoSave ({frequency}) of ₦{amount} was successful. It has been added to your SAVINGS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list, fail_silently=False)

    # Start a new thread for the auto charge process
    threading.Thread(target=auto_charge).start()

    user.autosave_enabled = True
    user.save()

    # Send an immediate email alert for activation
    subject = "AutoSave Activated!"
    message = f"Well done {user.first_name},\n\nAutoSave ({frequency}) was successfully activated. You are now saving ₦{amount} {frequency} and your next autosave transaction will happen in the next selected periodic interval. \n\n\nKeep growing your funds.🥂\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list, fail_silently=False)
    # Return a success response indicating that AutoSave has been activated
    return Response({'message': 'AutoSave activated'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deactivate_autosave(request):
    user = request.user
    frequency = request.data.get('frequency')

    try:
        # Find the active AutoSave for the user with the given frequency
        autosave = AutoSave.objects.get(user=user, frequency=frequency, active=True)

        # Deactivate the AutoSave by setting it to False
        autosave.active = False
        autosave.save()

        # Delete the AutoSave object from the database
        autosave.delete()

        user.autosave_enabled = False
        user.save()

        # Send a confirmation email
        subject = "AutoSave Deactivated!"
        message = f"Hi {user.first_name},\n\nYour AutoSave ({frequency}) has been deactivated. \n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

        # Return a success response indicating that AutoSave has been deactivated
        return Response({'message': 'AutoSave deactivated'}, status=status.HTTP_200_OK)

    except AutoSave.DoesNotExist:
        return Response({'error': 'AutoSave not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_autosave_status(request):
    user = request.user
    autosave_enabled = user.autosave_enabled
    
    # You can retrieve the user's active auto-save settings here
    try:
        active_autosave = AutoSave.objects.get(user=user, active=True)
        autoSaveSettings = {
            'active': True,
            'amount': active_autosave.amount,
            'frequency': active_autosave.frequency,
        }
    except AutoSave.DoesNotExist:
        autoSaveSettings = {
            'active': False,
            'amount': 0,
            'frequency': '',
        }
    
    return Response({'autosave_enabled': autosave_enabled, 'autoSaveSettings': autoSaveSettings}, status=status.HTTP_200_OK)




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def quickinvest(request):
    # Get the selected card details from the request
    card_id = request.data.get('card_id')
    amount = request.data.get('amount')

    # Retrieve the card details from your database
    try:
        card = Card.objects.get(id=card_id)
    except Card.DoesNotExist:
        return Response({'error': 'Selected card not found'}, status=status.HTTP_404_NOT_FOUND)

    # Use the card details to initiate a payment with Paystack
    paystack_secret_key = "sk_test_dacd07b029231eed22f407b3da805ecafdf2668f"  # Use your actual secret key
    paystack_url = "https://api.paystack.co/charge"

    payload = {
        "card": {
            "number": card.card_number,
            "cvv": card.cvv,
            "expiry_month": card.expiry_date.split('/')[0],
            "expiry_year": card.expiry_date.split('/')[1],
        },
        "email": request.user.email,  # Assuming you have a user authenticated with a JWT token
        "amount": int(amount) * 100,  # Amount in kobo (multiply by 100)
    }

    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
        "Content-Type": "application/json",
    }

    response = requests.post(paystack_url, json=payload, headers=headers)
    paystack_response = response.json()

    if paystack_response.get("status"):
        # Payment successful, update user's investments and create a transaction
        user = request.user
        user.investment += int(amount)
        user.save()

        # Send a confirmation email
        subject = "QuickInvest Successful!"
        message = f"Well done {user.first_name},\n\nYour QuickInvest was successful and ₦{amount} has been successfully added to your INVESTMENTS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        # Create a transaction record
        transaction = Transaction.objects.create(
            user=user,
            transaction_type="credit",
            amount=int(amount),
            date=timezone.now().date(),
            time=timezone.now().time(),
            description=f"QuickInvest",
            transaction_id=paystack_response.get("data", {}).get("reference"),
        )

        # Return a success response
        return Response({'message': 'QuickInvest successful', 'transaction_id': transaction.transaction_id}, status=status.HTTP_200_OK)
    else:
        # Payment failed, return an error response
        return Response({'error': 'QuickInvest failed'}, status=status.HTTP_400_BAD_REQUEST)
    


from .models import AutoInvest
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def autoinvest(request):
    user = request.user
    card_id = request.data.get('card_id')
    amount = request.data.get('amount')
    frequency = request.data.get('frequency')

    # Validate frequency (should be one of 'hourly', 'daily', 'weekly', 'monthly')
    valid_frequencies = ['hourly', 'daily', 'weekly', 'monthly']
    if frequency not in valid_frequencies:
        return Response({'error': 'Invalid frequency'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        active_autoinvest = AutoInvest.objects.get(user=user, active=True)
        return Response({'error': 'User already has an active autoinvest'}, status=status.HTTP_400_BAD_REQUEST)
    except AutoInvest.DoesNotExist:
        pass

    card = Card.objects.get(id=card_id)
    if not card:
        return Response({'error': 'Selected card not found'}, status=status.HTTP_404_NOT_FOUND)

    # Calculate the interval based on the selected frequency (in seconds)
    intervals = {
        'daily': 86400,
        'weekly': 604800,
        'monthly': 2419200,  # Approximation for 28-31 days
    }

    interval_seconds = intervals.get(frequency)

    if not interval_seconds:
        return Response({'error': 'Invalid frequency'}, status=status.HTTP_400_BAD_REQUEST)

    # Create an 'AutoInvest' record
    autoinvest = AutoInvest.objects.create(user=user, frequency=frequency, amount=amount, active=True)

    # Set the 'autoinvest_enabled' field to True
    user.autoinvest_enabled = True  # Add this line
    user.save()

    # Use the card details to initiate a payment with Paystack periodically
    def auto_invest():
        while True:
            # Delay for the specified interval
            time.sleep(interval_seconds)

            # Perform the auto invest
            paystack_secret_key = "sk_test_dacd07b029231eed22f407b3da805ecafdf2668f"  # Use your actual secret key
            paystack_url = "https://api.paystack.co/charge"

            payload = {
                "card": {
                    "number": card.card_number,
                    "cvv": card.cvv,
                    "expiry_month": card.expiry_date.split('/')[0],
                    "expiry_year": card.expiry_date.split('/')[1],
                },
                "email": user.email,
                "amount": int(amount) * 100,  # Amount in kobo (multiply by 100)
            }

            headers = {
                "Authorization": f"Bearer {paystack_secret_key}",
                "Content-Type": "application/json",
            }

            response = requests.post(paystack_url, json=payload, headers=headers)
            paystack_response = response.json()

            if paystack_response.get("status"):
                # Investment successful, update user's investments and create a transaction
                user.investment += int(amount)
                user.save()

                # Create a transaction record
                Transaction.objects.create(
                    user=user,
                    transaction_type="credit",
                    amount=int(amount),
                    date=timezone.now().date(),
                    time=timezone.now().time(),
                    description=f"AutoInvest",
                    transaction_id=paystack_response.get("data", {}).get("reference"),
                )

                # Send a confirmation email
                subject = "AutoInvest Successful!"
                message = f"Hi {user.first_name},\n\nYour AutoInvest ({frequency}) of ₦{amount} was successful. It has been added to your INVESTMENTS account. \n\nKeep growing your funds.🥂\n\n\nMyFund \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
                from_email = "MyFund <info@myfundmobile.com>"
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list, fail_silently=False)

    # Start a new thread for the auto invest process
    threading.Thread(target=auto_invest).start()

    # Send an immediate email alert for activation
    subject = "AutoInvest Activated!"
    message = f"Well done {user.first_name},\n\nAutoInvest ({frequency}) was successfully activated. You are now investing ₦{amount} {frequency} and your next AutoInvest transaction will happen in the next selected periodic interval. \n\n\nKeep growing your funds.🥂\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
    from_email = "MyFund <info@myfundmobile.com>"
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list, fail_silently=False)
    # Return a success response indicating that AutoInvest has been activated
    return Response({'message': 'AutoInvest activated'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deactivate_autoinvest(request):
    user = request.user
    frequency = request.data.get('frequency')

    try:
        # Find the active AutoInvest for the user with the given frequency
        autoinvest = AutoInvest.objects.get(user=user, frequency=frequency, active=True)

        # Deactivate the AutoInvest by setting it to False
        autoinvest.active = False
        autoinvest.save()

        # Delete the AutoInvest object from the database
        autoinvest.delete()

        user.autoinvest_enabled = False
        user.save()

        # Send a confirmation email
        subject = "AutoInvest Deactivated!"
        message = f"Hi {user.first_name},\n\nYour AutoInvest ({frequency}) has been deactivated. \n\nKeep growing your funds.🥂\n\n\nMyFund  \nSave, Buy Properties, Earn Rent \nwww.myfundmobile.com \n13, Gbajabiamila Street, Ayobo, Lagos, Nigeria."
        from_email = "MyFund <info@myfundmobile.com>"
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

        # Return a success response indicating that AutoInvest has been deactivated
        return Response({'message': 'AutoInvest deactivated'}, status=status.HTTP_200_OK)

    except AutoInvest.DoesNotExist:
        return Response({'error': 'AutoInvest not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_autoinvest_status(request):
    user = request.user
    autoinvest_enabled = user.autoinvest_enabled
    
    # You can retrieve the user's active auto-invest settings here
    try:
        active_autoinvest = AutoInvest.objects.get(user=user, active=True)
        autoInvestSettings = {
            'active': True,
            'amount': active_autoinvest.amount,
            'frequency': active_autoinvest.frequency,
        }
    except AutoInvest.DoesNotExist:
        autoInvestSettings = {
            'active': False,
            'amount': 0,
            'frequency': '',
        }
    
    return Response({'autoinvest_enabled': autoinvest_enabled, 'autoInvestSettings': autoInvestSettings}, status=status.HTTP_200_OK)
