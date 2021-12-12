import datetime

from kafka import KafkaProducer, KafkaConsumer
setting = {}
setting['AUTH_SERVER'] = '10.21.226.4:8000'
setting['BROKER_SERVER'] = '10.6.15.97:9092'
rec_n = 0
topic = 'kafka-security-topic'
consumer = KafkaConsumer(topic, bootstrap_servers=[setting['BROKER_SERVER']], )
for message in consumer:
    rec_n += 1
    if rec_n >= 50000:
        print(datetime.datetime.now())
        rec_n = 1
    # print(message.value.decode('UTF-8'))