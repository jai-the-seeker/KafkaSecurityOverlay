import requests
import jwt
from binascii import a2b_base64, b2a_base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


def byte_to_string(binbyte):
    return b2a_base64(binbyte).decode()


def encrypted_message(ss_key, string):
    cipher_aes = AES.new(ss_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(string.encode('utf-8'))
    return {'ciphertext': byte_to_string(ciphertext),
            'tag': byte_to_string(tag),
            'nonce': byte_to_string(cipher_aes.nonce)
            }


# curl -k -H 'Accept: application/json; indent=4' -u kafka_consumer:tZjSLzaCsDCT8x http://127.0.0.1:8000/token/
Broker_token, Client_token = None, None
username = 'kafka_producer'
key = 'jt9R7dRpDzEzFE'
with requests.Session() as s:
    s.auth = (username, key)
    s.headers.update({'Accept': 'application/json'})
    Client_token = s.get('https://10.21.226.4:8000/token/', verify=False).json()
    token = {
        'topic': 'kafka-security-topic',
        'role': 'producer',
        'client_acl_jwt': Client_token['acl_jwt']}

    Broker_token = jwt.encode(token, Client_token['keys']['private_key'], algorithm='RS256',
                              headers={'username': username})
print(Broker_token)
print(jwt.decode(Broker_token, Client_token['keys']['public_key'], algorithms='RS256'))

# with requests.Session() as client:
#     postURL = 'http://localhost:5000/auth/'
#     client.headers.update({'remote-user': username})
#     r = client.get(postURL)
#     csrft = r.cookies['csrftoken']
#     info = {'jwt': Broker_token, 'csrfmiddlewaretoken': csrft}
#     result = client.post(postURL, data=info, headers=dict(Referer=postURL))
#     getURL = 'http://localhost:5000/getkey/'
#
#     enc_key = client.get(getURL)
#     enc_session_key = a2b_base64(enc_key.text)
#     private_key = Client_token['keys']['private_key']
#     cipher_rsa = PKCS1_OAEP.new(RSA.importKey(private_key))
#     session_key = cipher_rsa.decrypt(enc_session_key)
#     session_key_str = byte_to_string(session_key)
#
#     produceURL = 'http://localhost:5000/prod/'
#     while(True):
#         inp = input('>')
#         print(client.post(produceURL, data=encrypted_message(session_key, inp)).text)

