from flask_socketio import emit, Namespace

class DeviceNamespace(Namespace):
    def on_connect(self):
        emit('message', {'msg': 'Device client connected'})

    def on_disconnect(self):
        pass

class AlertNamespace(Namespace):
    def on_connect(self):
        emit('message', {'msg': 'Alert client connected'})

    def on_disconnect(self):
        pass