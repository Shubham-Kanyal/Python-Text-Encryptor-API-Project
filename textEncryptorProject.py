#TEXT ENCRYPTOR PROJECT-
""" STEP-1: ENTER A STRING TEXT AS AN INPUT
    STEP-2: GENERATE AN ENCRYPTED MESSAGE OF THE SAME/DIFFERENT LENGTH AS THE ORIGINAL TEXT
    STEP-3: DISPLAY BOTH-THE ORIGINAL AND THE ENCRYPTED TEXTS
 """

import random 
import string
import requests     #USED TO CONNECT WITH THE 'hibpwned' API
import hashlib      #MAIN MAGIC HAPPENS HERE!
import time
from cryptography.fernet import Fernet

print('\n\n--------------------TEXT ENCRYPTOR PROJECT--------------------\n')

originalText = input("Enter a Text to Encrypt: ")


lenOrginalText = len(originalText)
print(f'Length of the Original Text: {lenOrginalText}')

encryptedTextDatabase = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'

encryptedText = ''

for i in range(0, lenOrginalText):
    encryptedText += (random.choice(encryptedTextDatabase))

print(f'\nOriginal Text: {originalText}')
print(f'Encrypted Text: {encryptedText}')

#--------------------------------------------------------------------------------------------------------
def checkPasswordInvolvedInDataBreach():
    pass

    #HaveIBeenPwned[HIBP] URL for checking if a password is pwned
    #HIBP Pwned Passwords API URL
    HIBP_PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/"
    password = originalText

    #SHA-1 and SHA-256 are the most widely-used HASHING ALGORITHMS
    #THE HASHED DATA CANNOT BE CONVERTED BACK INTO THE ORIGINAL TEXT MESSAGE-IT'S IRREVERSIBLE!

    # Step 1: Create the SHA-1 hash of the password (uppercased)
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Step 2: Get the first 5 characters of the hash (this is sent to the API)
    prefix = sha1_hash[:5]
    
    # Step 3: Get the rest of the hash to check against the API response
    suffix = sha1_hash[5:]
    
    # Step 4: Send the request to the HIBP API with the prefix
    response = requests.get(HIBP_PWNED_PASSWORDS_URL + prefix)
    
    # Step 5: Handle the API response
    if response.status_code == 200:
        # Step 6: Check if the suffix exists in the returned response
        pwned_passwords = response.text.splitlines()
        
        # Look through each line in the API response
        for pwned in pwned_passwords:
            hash_suffix, count = pwned.split(':')
            
            # If the hash suffix matches the rest of the password hash, it's pwned
            if hash_suffix == suffix:
                print(f"WARNING: Your password has been pwned {count} times! \n")
                return True
        
        # If no match is found
        print("Your password has NOT been pwned :) \n")
        return False
    else:
        # If the request fails
        print(f"Error: Unable to check password (HTTP Status: {response.status_code})")
        return False
#--------------------------------------------------------------------------------------------------------
def obtainCryptographicHash():
    print('\n---------------OBTAINING THE CRYPTOGRAPHIC HASH OF YOUR MESSAGE!---------------')
    time.sleep(5)
    print(f'\nOriginal Text: {originalText}')

    sha256OfOriginalText = hashlib.sha256()
    
    # Encode the originalText to bytes before updating
    sha256OfOriginalText.update(originalText.encode())

    originalTextHashed = sha256OfOriginalText.hexdigest()

    print(f'HASH: {originalTextHashed}')
#--------------------------------------------------------------------------------------------------------
def decryptEncryptedMessages():
    key = Fernet.generate_key()
    f = Fernet(key)
     
    # Convert originalText to bytes before encryption
    token = f.encrypt(originalText.encode())  # Encoding the string to bytes

    print(f'\nEncrypted Text: {encryptedText}')

    #Decrypting the token and decoding the bytes back to string
    print(f'Decrypted Text: {f.decrypt(token).decode()}\n')     #Decoding back to string

#--------------------------------------------------------------------------------------------------------

obtainCryptographicHash()
checkPasswordInvolvedInDataBreach()
decryptEncryptedMessages()
