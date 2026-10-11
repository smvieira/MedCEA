def clear_retained_messages(client,mqtt_url, mqtt_port, topic_prefix, timeout=10):
    """
    Connects to an MQTT broker, subscribes to the specified topic prefix,
    listens for a specified timeout, and returns a list of discovered topics.
    Exits if no topics are found within the timeout.

    Args:
        client (mqtt.Client): The MQTT client instance.
        mqtt_url (str): The URL or IP address of the MQTT broker.
        mqtt_port (int): The port number of the MQTT broker.
        topic_prefix (str): The MQTT topic prefix to subscribe to (e.g., "medcea/#").
        timeout (int, optional): The number of seconds to listen for messages before timing out.
                                 Defaults to 10 seconds.

    Returns:
        list: A sorted list of discovered MQTT topics under the specified prefix.
              Exits the program if no topics are discovered within the timeout.
    """
    import subprocess
    import time
    import paho.mqtt.client as mqtt
    import sys

    discovered_topics = set()
    connected_flag = False

    def on_connect(client, userdata, flags, rc):
        nonlocal connected_flag
        if rc == 0:
            connected_flag = True
            print(f"Connected to MQTT Broker: {mqtt_url}:{mqtt_port}")
            client.subscribe(topic_prefix)
            print(f"Subscribed to: {topic_prefix}")
        else:
            print(f"Failed to connect, return code {rc}")

    def on_message(client, userdata, msg):
        discovered_topics.add(msg.topic)
        print(f"Discovered topic: {msg.topic}")
        print("\nClearing retained messages for each topic using mosquitto_pub...")
        # Use mosquitto_pub to clear the retained message
        # by publishing an empty message with the retain flag set
        publish_command = [
            "mosquitto_pub",
            "-h", mqtt_url,
            "-p", str(mqtt_port),
            "-t", msg.topic,
            "-n",  # Null payload
            "-r"   # Retain flag
            ]
        try:
            result = subprocess.run(publish_command, capture_output=True, text=True, check=True)
            print(f"Cleared retained message for: {msg.topic}")
            if result.stderr:
                print(f"  Stderr: {result.stderr.strip()}")
        except subprocess.CalledProcessError as e:
            print(f"Error clearing retained message for {msg.topic}:")
            print(f"  Command: {e.cmd}")
            print(f"  Return Code: {e.returncode}")
            print(f"  Stdout: {e.stdout.strip()}")
            print(f"  Stderr: {e.stderr.strip()}")
        except FileNotFoundError:
            print("Error: mosquitto_pub not found. Make sure mosquitto-clients is installed and in your PATH.")
            return
        except Exception as e:
            print(f"An unexpected error occurred while clearing {msg.topic}: {e}")
        

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(mqtt_url, mqtt_port, 60)
        client.loop_start()  # Start the MQTT network loop in the background

        start_time = time.time()
        while time.time() - start_time < timeout:
            if connected_flag:
                time.sleep(0.1)  # Give time for messages to arrive
            else:
                time.sleep(1)  # Wait for connection

        client.loop_stop()  # Stop the MQTT network loop
        client.disconnect()

        if not discovered_topics:
            print(f"No topics found under the prefix: {topic_prefix} within {timeout} seconds. Exiting.")
            return []
        else:
            sorted_topics = sorted(list(discovered_topics))
            print("\nDiscovered Topics:")
            for topic in sorted_topics:
                print(topic)
            return sorted_topics
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)