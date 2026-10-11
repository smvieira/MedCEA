def mqtt_publish_control_message(client, topic, payload, publish_type="normal"):
    """
    Publishes a control message to a topic based on the publish_type.

    - If publish_type="normal", publishes to a new topic by replacing '/sense/' with '/control/'
      in the original topic.
    - If publish_type="finished", publishes to a topic keeping the first two sections of the
      original topic and appending 'all_controllers_off' with an informative payload.

    Args:
        client: The MQTT client instance.
        topic (str): The original MQTT topic (e.g., 'medcea/UNIT01/ZONE01/sense/substrate_temperature').
        payload (dict): The payload to publish (e.g., {"command": "ON", "value": 25}).
        publish_type (str, optional): The type of publish operation. Defaults to "normal".
                                       Can be "normal" or "finished".
    """
    import os
    import json
    from datetime import datetime
    import socket
    import uuid
    import time

    current_time = time.strftime('%Y-%m-%d %H:%M:%S')

    mqtt_url = os.getenv('MQTT_URL')
    mqtt_port = int(os.getenv('MQTT_PORT'))
    # Add device-specific information to the payload
    # Get the MAC address
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
    payload["device_id"] = mac_address
    # Get the hostname
    hostname = socket.gethostname()
    payload["device_dns"] = hostname
    # Get Unit code and zone code from the topic
    # Assuming the topic is structured as 'medcea/UNIT01/ZONE01/sense/substrate_temperature'
    # Overwrite if already in payload
    payload["unit_code"] =  topic.split('/')[1]  # Extract unit code from the topic
    payload["zone_code"] = topic.split('/')[2]  # Extract zone code from the topic
    payload['msg_type']  = "CT"
#    client.connect(mqtt_url, mqtt_port)

    control_topic = topic.replace("/sense/", "/control/")
    #print(f"Control topic: {control_topic}")
    #print(f"Original topic: {topic}")
    if publish_type == "normal":
        json_payload = json.dumps(payload)
    elif publish_type == "finished":
        payload = {
            "message": "All control processes finished for this unit/context.",
            "tag":"all_controllers_off",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "original_topic": topic,
            "summary": payload
            }
        json_payload = json.dumps(payload)
        control_topic=control_topic.replace("/#", "/all_controllers_off")
        print(f"[{current_time}] Published shutdown message to {control_topic}")
    else:
        raise ValueError(f"[{current_time}] Unknown publish_type '{publish_type}'. Expected 'normal' or 'finished'.")

    client.publish(control_topic, json_payload, qos=1)
    
    
