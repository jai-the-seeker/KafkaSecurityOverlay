from binascii import b2a_base64, a2b_base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt


def loginView(request):
    request.session['enc_key'] = None
    if request.method == 'POST':
        if request.user.is_authenticated:
            response = HttpResponse("Successfully Authenticated")
        else:
            response = HttpResponse("Authentication Failure")
        return response
    else:
        response = HttpResponse("Send By POST")
        csrft = get_token(request)
        response.set_cookie('csrftoken', csrft)
        return response


def str_to_bytes(string):
    return a2b_base64(string)

@login_required
def getEncryptionKey(request):
    if request.method == 'GET':
        if request.session['enc_key'] is None:
            request.session['enc_key'] = b2a_base64(get_random_bytes(16)).decode()
        session_key = str_to_bytes(request.session['enc_key'])
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(request.session['client_key']))
        key_out = b2a_base64(cipher_rsa.encrypt(session_key)).decode()
        return HttpResponse(key_out)
    else:
        return HttpResponse('Use GET')



@login_required
@csrf_exempt
def produceMessage(request):
    if request.method == 'POST':
        ciphertext = str_to_bytes(request.POST['ciphertext'])
        tag = str_to_bytes(request.POST['tag'])
        nonce = str_to_bytes(request.POST['nonce'])
        cipher_aes = AES.new(str_to_bytes(request.session['enc_key']),
                             AES.MODE_EAX,
                             nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        producer = KafkaProducer(bootstrap_servers=[setting['BROKER_SERVER']])
        future =  producer.send(request.session['topic'], data)
        print(data.decode("utf-8"), request.session['topic'], request.user.__str__())
        return HttpResponse('Data Received')
    else:
        return HttpResponse('Send By POST')
