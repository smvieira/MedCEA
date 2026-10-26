def mqtt_subscribe_thread(client, mqtt_topics, instance_shared_data, data_lock, stop_event):
    """Thread for MQTT subscription."""
    import threading
    import json
    import os
    import time
    import sys
    #data_lock = threading.Lock()  # Ensure threading is used from the imported module
    shared_data = instance_shared_data  # Assuming shared_data is defined in the imported module

    mqtt_url=os.getenv('MQTT_URL')
    mqtt_port=int(os.getenv('MQTT_PORT'))

# callback functions
    def on_disconnect(client, userdata, rc):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] MQTT Disconnected with result code: {rc}. Attempting reconnect if Paho configured.")
        if rc != 0:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] <Error> Unexpected MQTT Disconnection. Attempting reconnect if Paho configured.")
            client.reconnect()
  
    def on_connect(client, userdata, flags, rc):
        """Callback when the client connects to the MQTT broker."""
        if rc == 0:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Connected to MQTT Broker!")
            for topic in mqtt_topics:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Subscribing to {topic}")
                client.subscribe(topic)
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Subscribed to {topic}")
        else:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] <Error> Failed to connect, return code {rc}")



    # in on_message within mqtt_subscribe_thread.py
    def on_message(client, userdata, msg):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        try:
            payload = json.loads(msg.payload.decode())
            with data_lock:
                shared_data[msg.topic] = payload
        except json.JSONDecodeError as jde:
            print(f"[{current_time}] <Error> MQTT JSONDecodeError for topic {msg.topic}: {jde}. Payload: {msg.payload.decode(errors='replace')}", file=sys.stderr)
        except Exception as e:
            print(f"[{current_time}] <Error> failed processing message in MQTT thread for topic {msg.topic}: {e}", file=sys.stderr)
 


 
 # Register callbacks
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    # Credentials were set with username_pw_set where the client was built.
    client.connect(mqtt_url, mqtt_port)

    # in mqtt_subscribe_thread.py, inside the while loop
    while not stop_event.is_set():
        client.loop(timeout=1.0)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] mqtt_subscribe_thread loop terminated.")
