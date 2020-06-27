from flask import Flask, render_template
from flask import request
import core_signature

app = Flask(__name__)


@app.route('/')
def index_signature():
    return render_template("rsa_index.html", public_key="signature public key", private_key="signature private key",
                           show_form1=True, show_form2=True, show_form3=True)


@app.route('/generate-key', methods=['POST'])
def generate_key_signature():
    option = request.form['options']
    if option == "512":
        a, b = core_signature.signature_generate_key(512)
    elif option == "1024":
        a, b = core_signature.signature_generate_key(1024)
    elif option == "2048":
        a, b = core_signature.signature_generate_key(2048)
    elif option == "4096":
        a, b = core_signature.signature_generate_key(4096)
    return render_template("rsa_index.html", public_key=a, private_key=b, show_form1=True, show_form2=True,
                           show_form3=True)


@app.route('/signature-message', methods=['POST'])
def message_signature():
    message_send = request.form['message_send']
    option = request.form['options']
    if option == "SHA-256":
        signature_message = core_signature.signature_message_hash(message_send, 'SHA-256')
    elif option == "SHA-384":
        signature_message = core_signature.signature_message_hash(message_send, 'SHA-384')
    elif option == "SHA-512":
        signature_message = core_signature.signature_message_hash(message_send, 'SHA-512')
    return render_template("rsa_index.html", signature_message=signature_message, show_form1=False, show_form2=True,
                           show_form3=True)


@app.route('/signature-verify', methods=['POST'])
def verify_signature():
    message_receive = request.form['message_receive']
    signature_verify = core_signature.signature_verify(message_receive)
    return render_template("rsa_index.html", signature_verify=signature_verify, show_form1=False, show_form2=False,
                           show_form3=False)


if __name__ == '__main__':
    app.run(host='127.29.07.98', debug=True)
