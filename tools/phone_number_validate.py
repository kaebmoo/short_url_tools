import phonenumbers

phonenumbers.PhoneMetadata.load_all()
try:
    phone = "66813520625"
    x = phonenumbers.parse(phone, "TH")
    print(x)
    valid = phonenumbers.is_valid_number(x)
    print(valid)
    if valid:
        phone_number = phonenumbers.format_number(x, phonenumbers.PhoneNumberFormat.NATIONAL) # NATIONAL, INTERNATIONAL, E164
        print(phone_number)  
    else:
        print("The phone number format is incorrect.")
except phonenumbers.NumberParseException as e:
    print(e)
