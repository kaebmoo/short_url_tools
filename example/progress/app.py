from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # กำหนด secret key สำหรับ SocketIO
socketio = SocketIO(app)  # เปิดใช้งาน SocketIO และอนุญาต CORS

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def on_connect():
    print('Client connected')

@socketio.on('start_progress')
def start_progress():
    for i in range(101):
        emit('progress_update', {'progress': i})
        socketio.sleep(0.2)  # จำลองการทำงานที่ใช้เวลา

if __name__ == '__main__':
    socketio.run(app, debug=True, port=9000)