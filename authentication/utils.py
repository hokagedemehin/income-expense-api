from django.core.mail import EmailMessage
class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'],from_email="ibk2k7@gmail.com",to=[data['email_to']])
        email.send()