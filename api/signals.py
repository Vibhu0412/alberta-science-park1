from .models import *
from django.dispatch import Signal, receiver

create_business_profile = Signal()

@receiver(create_business_profile)
def custom_signal(sender,**kwargs):
    BusinessInformation.objects.create(userid=kwargs['userid'],
                                       user_id = kwargs['userid'],
                                       company_name=kwargs['company_name'],
                                       company_description=kwargs['company_description'],
                                       company_website=kwargs['company_website'],
                                       company_phone=kwargs['company_phone'],
                                       company_address_line_1=kwargs['company_address_line_1'],
                                       company_address_line_2=kwargs['company_address_line_2'],
                                       company_classification=kwargs['company_classification'],
                                       company_city=kwargs['company_city'],
                                       company_state=kwargs['company_state'],
                                       company_country=kwargs['company_country']
                                       )
