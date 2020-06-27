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
    # write the public key to a file
    with open('signature_key/public_key.key', 'wb') as key_file:
        key_file.write(public_key.save_pkcs1('PEM'))

    # write the private key to a file
    with open('signature_key/private_key.key', 'wb') as key_file:
        key_file.write(private_key.save_pkcs1('PEM'))


def signature_hash_message(hash_type):
    # hash_type = {SHA-224, SHA-256, SHA-384, SHA-512}
    # open private key file and load in key
    private_Key = rsa.PrivateKey.load_pkcs1(file_open('signature_key/private_key.key'))
    # open the secret message file and return data to variable
    message = file_open('message_signer/message')
    hash_value = rsa.compute_hash(message, hash_type)
    # sign the message with owners private key
    signature = rsa.sign(message, private_Key, hash_type)
    # save signature
    s = open('signature_key/signature_file', 'wb')
    s.write(signature)


def signature_information():
    print("Information signature:\n")
    # print private key
    private_key = file_open('signature_key/private_key.key')
    print("private key:\n", private_key)
    # print public key
    private_key = file_open('signature_key/public_key.key')
    # print(type(private_key))
    print("private key:\n", private_key)
    # print message
    message = file_open('message_signer/message')
    print("message:\n", message)
    # print signature
    signature = file_open('signature_key/signature_file')
    print("signature:\n", binascii.hexlify(signature))
    print(len(binascii.hexlify(signature)))


def signature_verify():
    # open public key file and load in key
    public_Key = rsa.PublicKey.load_pkcs1(file_open('signature_key/public_key.key'))
    message = file_open('message_signer/message_fake')
    signature = file_open('signature_key/signature_file')
    # verify the signature to show if successful of failed
    try:
        rsa.verify(message, signature, public_Key)
        print("Signature successfully verified!")
    except:
        print("Warning!! signature could not be verified")


if __name__ == '__main__':
    signature_generate_key(2048)
    signature_hash_message('SHA-256')
    signature_information()
    signature_verify()