import socketio 
from Crypto.PublicKey import RSA  # For RSA public key encryption
from Crypto.Random import get_random_bytes  # For AES key generation
from Crypto.Cipher import PKCS1_OAEP,AES
import ast

# Add PKCS7 padding to make plaintext length a multiple of AES block size (16 bytes)
def add_pkcs7_padding(data):
    pad_len = 16 - (len(data) % 16) 
    return data + bytes([pad_len] * pad_len) 


def pkcs7_padding(data):
    last_byte = data[-1]                            
    if last_byte < 1 or last_byte > 16:              
        return False
    if data[-last_byte:] != bytes([last_byte] * last_byte):  
        return False
    return True


def remove_pkcs7_padding(data):
    if not pkcs7_padding(data):                      
        raise ValueError("Invalid PKCS7 padding.")
    return data[:-data[-1]]                          


sio = socketio.Client()
rsa_PubKey = None  
aes_key=None 
should_exit = False 
aes_encrypted_key = None 


@sio.on('connect')
def on_connect():
    
    print("Connected to server!\n")

@sio.on('disconnect')
def on_disconnect():
    print("Disconnected from server.\n") 


@sio.on('message')
def receive_message(msg):
    global rsa_PubKey,should_exit,aes_key,aes_encrypted_key

    if rsa_PubKey is None:
        
        rsa_PubKey = RSA.importKey(ast.literal_eval((msg))) #converts strings to bytes
        print("got the public key from server\n")
        
        print("Public key received from server:", rsa_PubKey.exportKey('DER'),"\n")

        aes_key=get_random_bytes(16)
        print("AES key generated: ",aes_key,"\n") #generates aes key, 128bits

        encryptor=PKCS1_OAEP.new(rsa_PubKey) #Encrypt AES key using RSA public key
        aes_encrypted_key=encryptor.encrypt(aes_key)
        print("AES key encrypted with RSA: ", aes_encrypted_key,"\n")

        sio.send(str(aes_encrypted_key)) 
        send_message() 

    elif msg.lower() =='bye':
        print("Server disconnected\n")
        should_exit = True
        sio.disconnect()
        return
        
    else:

        msg_bytes = ast.literal_eval(msg)
        iv = msg_bytes[:16]
        ciphertext = msg_bytes[16:] #converts received string back to server
    
        print("Encrypted message from server:", msg_bytes,"\n")

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)  #decrypts the message
        decrypted_data = cipher.decrypt(ciphertext)
        plaintext = remove_pkcs7_padding(decrypted_data).decode()

        print("Decrypted message from server:", plaintext,"\n")

        if not should_exit:
            send_message() #it asks for new input
    
def send_message(): 
    global should_exit,aes_key
    msg = input("Send a message to server: \n")
    if msg.lower() == 'bye':
        print("Client disconnected!\n")
        sio.send('bye')
        should_exit = True
        sio.disconnect()
        return
    
    iv=get_random_bytes(16) #generates iv for messages

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_msg = add_pkcs7_padding(msg.encode())
    ciphertext = cipher.encrypt(padded_msg)

    print("Encrypted message to server:", ciphertext,"\n")
    encrypted_payload = iv + ciphertext
    sio.send(str(encrypted_payload))


sio.connect('http://localhost:5000') #Connect to the server running on my own computer (localhost) at port 5000

sio.wait() 