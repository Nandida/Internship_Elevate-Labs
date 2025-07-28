from flask import Flask,request #flask- sets up your web server
from flask_socketio import SocketIO,disconnect 
from Crypto.PublicKey import RSA #for rsa key generation
from Crypto.Cipher import PKCS1_OAEP,AES #padding scheme for rsa encrption/decryption. 
from Crypto.Random import get_random_bytes 
import ast

def pkcs7_padding(data): 
    last_byte = data[-1] 
    if last_byte < 1 or last_byte > 16: 
        return False
    if data[-last_byte:] != bytes([last_byte] * last_byte): 
        
        return False
    return True 


def remove_pkcs7_padding(data):
    if not pkcs7_padding(data):
        print("Invalid padding.\n")
        return data  
    return data[:-data[-1]]

app = Flask(__name__) 
app.config['SECRET_KEY'] = 'secret' 
socketio = SocketIO(app, cors_allowed_origins="*") 


#RSA generation
key=RSA.generate(2048)
binPrivKey= key.exportKey('DER') 
binPubKey= key.publickey().exportKey('DER')     

clients={} 

@socketio.on('connect') 
def handle_connect(): 
    sid=request.sid 
    print(" A client has connected.\n") 
    socketio.send(str(binPubKey)) #sends rsa to client
    print("Public key sent to the client:" ,binPubKey,"\n")


@socketio.on('message') 
def receive_message(msg):
    sid=request.sid 

    if msg.lower() == 'bye':
        print("Client disconnected!\n") 
        disconnect()
        return

    if sid not in clients:
     print("Recieved encrypted AES key from client: ",msg,"\n")
     encrypted_aes_key=ast.literal_eval(msg) 
     decryptor=PKCS1_OAEP.new(RSA.import_key(binPrivKey))
     aes_key=decryptor.decrypt(encrypted_aes_key) 
     clients[sid]=aes_key #stores AES key
     print("Decrypted AES key from client: ",aes_key,"\n")
     return

    msg_bytes = ast.literal_eval(msg) 
    iv = msg_bytes[:16] 
    ciphertext = msg_bytes[16:] 

    print("Encrypted message from client:", msg_bytes,"\n")

    with open("chat_logs.txt", "a") as f:
        f.write("From client: " + str(msg_bytes) + "\n")


    cipher = AES.new(clients[sid], AES.MODE_CBC, iv=iv)
    decrypted_data = cipher.decrypt(ciphertext) 
    plaintext = remove_pkcs7_padding(decrypted_data).decode() 

    print("Decrypted message from client:", plaintext,"\n")

    send_message(sid) 
    
def send_message(sid): 
    msg = input("Send a message to client: \n") 
    if msg.lower() == 'bye':
        socketio.send('bye', to=sid)
        print("Server disconnected!\n")
        disconnect()
        return
    
    padded_msg = msg.encode() 
    pad_len = 16 - (len(padded_msg) % 16) 
    padded_msg += bytes([pad_len] * pad_len) 

    iv = get_random_bytes(16)  
    cipher = AES.new(clients[sid], AES.MODE_CBC, iv=iv)
    encrypted_msg = cipher.encrypt(padded_msg) 

    print("Encrypted message to client:", iv + encrypted_msg, "\n") 
    with open("chat_logs.txt", "a") as f:
        f.write("To client: " + str(iv + encrypted_msg) + "\n")

    socketio.send(str(iv + encrypted_msg), to=sid) 


if __name__ == '__main__':
    print(" Server running at http://localhost:5000") 
    socketio.run(app) 
    