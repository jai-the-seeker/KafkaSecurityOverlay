import asyncio
import datetime

import websockets
import ssl
import pathlib
import requests
import jwt

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
localhost_pem = pathlib.Path(__file__).with_name("server.pem")
ssl_context.load_verify_locations(localhost_pem)


def get_token(username, key):
    with requests.Session() as s:
        s.auth = (username, key)
        s.headers.update({'Accept': 'application/json'})
        Client_token = s.get('https://10.21.226.4:8000/token/', verify=False).json()
        token = {
            'topic': 'kafka-security-topic',
            'role': 'consumer',
            'client_acl_jwt': Client_token['acl_jwt']}

        return jwt.encode(token, Client_token['keys']['private_key'], algorithm='RS256',
                          headers={'username': username})


async def consume(username, key):
    uri = "wss://localhost:8765"
    token = None
    rec_n = 0
    try:
        token = get_token(username, key)
    except Exception as e:
        print("unable to get token becase " + str(e))
        return

    async for websocket in websockets.connect(uri, ssl=ssl_context):
        await websocket.send(token)
        try:
            await websocket.ping()
            print('pinged')
            while True:
                async for message in websocket:
                    rec_n += 1
                    if rec_n >= 50000:
                        print(datetime.datetime.now())
                        rec_n = 1
        # except websockets.ConnectionClosed:
        finally:
            print("closed")
            await websocket.close()
            return


asyncio.run(consume('kafka_consumer', 'tZjSLzaCsDCT8x'))
