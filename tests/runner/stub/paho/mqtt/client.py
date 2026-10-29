"""paho.mqtt.client stand-in for tests/iam-runner.sh: the runner's agent talks to no
broker in the throwaway namespace. Every call succeeds; publishes are recorded in
PUBLISHED and printed, so the run's log shows what would have been sent."""
import time

PUBLISHED = []


class _Info:
    rc = 0
    mid = 1

    def wait_for_publish(self, timeout=None):
        return True

    def is_published(self):
        return True


class Client:
    def __init__(self, client_id="", *args, **kwargs):
        self.client_id = client_id
        self.on_connect = self.on_message = self.on_disconnect = None

    def username_pw_set(self, username, password=None):
        self.username = username

    def connect(self, host, port=1883, keepalive=60, *args, **kwargs):
        if self.on_connect:
            self.on_connect(self, None, {}, 0)
        return 0

    def reconnect(self):
        return 0

    def loop(self, timeout=1.0, *args, **kwargs):
        time.sleep(min(timeout, 0.2))
        return 0

    def loop_start(self):
        return 0

    def loop_stop(self, *args, **kwargs):
        return 0

    def subscribe(self, topic, qos=0, *args, **kwargs):
        return (0, 1)

    def publish(self, topic, payload=None, qos=0, retain=False, *args, **kwargs):
        PUBLISHED.append((topic, payload))
        print(f"[paho stub] publish {topic}")
        return _Info()

    def disconnect(self, *args, **kwargs):
        if self.on_disconnect:
            self.on_disconnect(self, None, 0)
        return 0
