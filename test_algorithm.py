import rsa


def file_open(file):
    key_file = open(file, 'rb')
    key_data = key_file.read()
    key_file.close()
    return key_data


public_Key = rsa.PublicKey.load_pkcs1(file_open('signature_key/public_key.key'))
print(public_Key)
message = file_open('message_signer/message')
print(message)
signature = file_open('signature_key/signature_file')
print(signature)
try:
    rsa.verify(message, signature, public_Key)
    print("Signature successfully verified!")
except:
    print("Warning!! signature could not be verified")