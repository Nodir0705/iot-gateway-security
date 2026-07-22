#!/usr/bin/env python3
"""MQTT Alert Publisher — sends detection alerts to MQTT broker"""
import paho.mqtt.client as mqtt
import json
import time
import os

BROKER = "localhost"
PORT = 1883
TOPIC_ALERT = "iot-gateway/alerts"
TOPIC_STATUS = "iot-gateway/status"
TOPIC_QUARANTINE = "iot-gateway/quarantine"

class MQTTAlerter:
    def __init__(self, broker=BROKER, port=PORT):
        self.client = mqtt.Client(client_id="iot-gateway-alerter")
        self.client.on_connect = self._on_connect
        self.connected = False
        try:
            self.client.connect(broker, port, 60)
            self.client.loop_start()
            time.sleep(1)
        except Exception as e:
            print(f"MQTT connection failed: {e}")

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            print(f"MQTT connected to {BROKER}:{PORT}")
        else:
            print(f"MQTT connection failed: rc={rc}")

    def send_alert(self, alert_data):
        """Publish an alert to MQTT"""
        if not self.connected:
            return False
        payload = json.dumps({
            "timestamp": time.time(),
            "type": "alert",
            **alert_data,
        })
        self.client.publish(TOPIC_ALERT, payload, qos=1)
        return True

    def send_quarantine(self, ip, action, reason=""):
        """Publish quarantine action"""
        if not self.connected:
            return False
        payload = json.dumps({
            "timestamp": time.time(),
            "type": "quarantine",
            "ip": ip,
            "action": action,
            "reason": reason,
        })
        self.client.publish(TOPIC_QUARANTINE, payload, qos=1)
        return True

    def send_status(self, stats):
        """Publish gateway status"""
        if not self.connected:
            return False
        payload = json.dumps({
            "timestamp": time.time(),
            "type": "status",
            **stats,
        })
        self.client.publish(TOPIC_STATUS, payload, qos=0)
        return True

    def close(self):
        self.client.loop_stop()
        self.client.disconnect()

if __name__ == '__main__':
    alerter = MQTTAlerter()
    if alerter.connected:
        alerter.send_alert({
            "src_ip": "192.168.3.100",
            "dst_ip": "192.168.3.1",
            "score": 0.85,
            "signature": "IOT Mirai credential - admin/admin",
            "severity": 1,
        })
        alerter.send_status({
            "packets_total": 12345,
            "alerts_total": 5,
            "flows_active": 42,
            "backend": "rknn",
        })
        print("Test alerts sent")
        time.sleep(1)
        alerter.close()
    else:
        print("MQTT not available — alerts will be logged only")
