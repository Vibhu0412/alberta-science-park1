import os
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.template.loader import render_to_string


class Util:
    # @staticmethod
    # def send_email(data, link, company_name):
        # accept_link = link+'&accept='+str(True)
        # reject_link = link+'&accept='+str(False)
        # print("ACCEPT==", accept_link)
        # print("Reject==", reject_link)
        # # email_plaintext_message = render_to_string('invitelink.txt')
        # email_html_message = render_to_string('invitelink.html', context={
        #     'company_name':company_name,
        #     'accept_link':accept_link,
        #     'reject_link':reject_link
        # })
        # msg = EmailMessage(
        #     subject = data['subject'],
        #     body= email_html_message,
        #     from_email='no-reply@thesciencepark.dev',
        #     to = [data['to_email']]
        # )
        # msg.content_subtype = "html"
        # # print('EMail**********************', msg)
        # # msg.attach_alternative(email_html_message, "text/html")
        # msg.send()
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email='no-reply@thesciencepark.dev',
            # from_email='vbpurohit1948@gmail.com',
            to=(data['to_email'],),
        )
        email.send()

