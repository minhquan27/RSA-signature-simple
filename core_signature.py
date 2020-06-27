import rsa
import binascii


def file_open(file):
    key_file = open(file, 'rb')
    key_data = key_file.read()
    key_file.close()
    return key_data


def signature_generate_key(key_size):
    # key_size = {512, 1024, 2048, 4096}
    # create the public key and private key
    (public_key, private_key) = rsa.newkeys(key_size)
    a = public_key.save_pkcs1()
    b = private_key.save_pkcs1()
    with open('signature_user/public_key_user.key', 'wb') as key_file:
        key_file.write(public_key.save_pkcs1('PEM'))

        # write the private key to a file
    with open('signature_user/private_key_user.key', 'wb') as key_file:
        key_file.write(private_key.save_pkcs1('PEM'))
    return a, b


def signature_message_hash(message_send, hash_type):
    message_send = message_send.encode()
    private_key = rsa.PrivateKey.load_pkcs1(file_open('signature_user/private_key_user.key'))
    signature_message = rsa.sign(message_send, private_key, hash_type)
    # signature_message = binascii.hexlify(signature_message)
    s = open('signature_user/signature_file', 'wb')
    s.write(signature_message)
    return signature_message


def signature_verify(message_receive):
    message_receive = message_receive.encode()
    public_key = rsa.PublicKey.load_pkcs1(file_open('signature_user/public_key_user.key'))
    signature_message = file_open('signature_user/signature_file')
    try:
        rsa.verify(message_receive, signature_message, public_key)
        return "Signature successfully verified!"
    except:
        return "Warning!! signature could not be verified"
