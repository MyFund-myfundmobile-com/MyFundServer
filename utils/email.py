import os
import resend

resend.api_key = os.environ.get("RESEND_API_KEY")


def send_otp_email(user, otp):
    resend.Emails.send(
        {
            "from": "MyFund <noreply@myfundmobile.com>",
            "to": user.email,
            "subject": "Your MyFund OTP",
            "html": f"<h2>{otp}</h2><p>Your OTP code</p>",
        }
    )
