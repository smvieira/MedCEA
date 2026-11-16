def mqtt_subscribe_thread(client, mqtt_topics, instance_shared_data, data_lock, stop_event,
                          root=None, unit_code=None):
    """Thread for MQTT subscription.

    mqtt_topics: a list of <root>/<unit>/<zone>/sense/# (every zone of the loop map;
    re-subscribed after a reconnect). Each reading is parsed by
    loop_resolver.parse_reading_topic (5- and 6-segment topics, Q12) and stored as
    instance_shared_data[(zone, tag, sensor)] = (value, receive time), the receive
    time being this process's time.monotonic() (the board's timestamp is never
    trusted). Anything else (_health, _test, other units) is ignored.
    """
    import json
    import os
    import time
    import sys
    from cea import loop_resolver
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



    _bad_value_logged = set()

    def on_message(client, userdata, msg):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        recv_t = time.monotonic()
        try:
            payload = json.loads(msg.payload.decode())
            key = loop_resolver.parse_reading_topic(msg.topic, root, unit_code, payload)
            if key is None:
                return
            with data_lock:
                stored = loop_resolver.update_readings(shared_data, key, payload, recv_t)
            if not stored and loop_resolver.reading_value(payload) is None and key not in _bad_value_logged:
                _bad_value_logged.add(key)
                print(f"[{current_time}] <Warning> no numeric value on {msg.topic} (logged once per sensor)", file=sys.stderr)
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
