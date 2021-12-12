# WS server example

import asyncio
import websockets
import ssl
import pathlib
import json
import requests
import jwt
from kafka import KafkaProducer, KafkaConsumer
from aiokafka import AIOKafkaConsumer

connected = set()

setting = {}
setting['AUTH_SERVER'] = '10.21.226.4:8000'
setting['BROKER_SERVER'] = '10.6.15.97:9092'


def authenticate(token):
    usr = jwt.get_unverified_header(token)['username']
    s = requests.Session()
    s.auth = ('broker', '6prZrrNwwQ5X54')
    s.headers.update({'Accept': 'application/json'})
    keys = None
    keys = s.get('https://' + setting['AUTH_SERVER'] + '/pubkey/', verify=False, params={'username': usr}).json()

    client_decode = None
    try:
        client_decode = jwt.decode(token, keys['client']['public_key'], algorithms=['RS256'])
    except Exception as e:
        return None, None
    server_decode = None
    try:
        server_decode = jwt.decode(client_decode['client_acl_jwt'], keys['server'], algorithms=['RS256'])
    except Exception as e:
        return None, None

    for ele in server_decode['acl_payload']:
        if client_decode['topic'] == ele['topic']:
            if ele[client_decode['role']]:
                return client_decode['topic'], client_decode['role']
    return None, None



async def handler(websocket, request_uri):
    jwt_token = await websocket.recv()
    topic, role = authenticate(jwt_token)
    if topic is None or role is None:
        await websocket.close(1011, reason="wrong credentials")
        return

    try:
        if role == 'producer':
            print('producer')
            producer = KafkaProducer(bootstrap_servers=[setting['BROKER_SERVER']])
            while True:
                messg = await websocket.recv()
                if type(messg) == str:
                    messg = messg.encode('UTF-8')
                future = producer.send(topic, messg)
        else:
            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=setting['BROKER_SERVER']
            )
            await consumer.start()
            print('consumer connected')
            try:
                async for msg in consumer:
                    await websocket.send(msg.value.decode('utf-8'))
            finally:
                await consumer.stop()
    finally:
        print('disconnected')
        await websocket.close()
        return



ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
localhost_pem = pathlib.Path(__file__).with_name("server.pem")
ssl_context.load_cert_chain(localhost_pem)


async def main_server():
    async with websockets.serve(handler, "localhost", 8765, ssl=ssl_context, ping_timeout=None, close_timeout=None):
        await asyncio.Future()  # run forever


asyncio.run(main_server())
