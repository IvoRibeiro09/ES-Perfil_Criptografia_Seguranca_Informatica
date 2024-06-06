from flask import Flask, request, jsonify
from server_scripts import *
from Auth_cert.Auth_cert import load_data
from user import *
import jwt
from jwcrypto import jwe,jwk
import datetime
import base64

if not os.path.exists("server"):
    os.makedirs("server")
if not os.path.exists("server/pks"):
    os.makedirs("server/pks")

arquivo_existe = os.path.isfile("server/log.csv")
# Se o arquivo não existir, adicionar um cabeçalho
if not arquivo_existe:
    with open("server/log.csv", mode='a+', newline='') as arquivo_csv:
        escritor_csv = csv.writer(arquivo_csv)
        escritor_csv.writerow(['NUM','SENDER','TIME', 'SUBJECT','RECEIBER',"LIDA"])
private_key, public_key, certificate = load_data('server')

pk = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
with open("server/pks/server.pk", "wb+") as f:
    f.write(pk)
users = []
uids = [nome for nome in os.listdir('server')]
uids.remove('pks')
uids.remove('log.csv')
for uid in uids:
    caminho_do_diretorio = f'server/{uid}/env'
    if os.path.exists(caminho_do_diretorio):
        numero_de_env = len(os.listdir(caminho_do_diretorio))
    else:
        numero_de_env = 0
    caminho_do_diretorio = f'server/{uid}/rec'
    if os.path.exists(caminho_do_diretorio):
        numero_de_rec = len(os.listdir(caminho_do_diretorio))
    else:
        numero_de_rec = 0
    user = User(uid,env=numero_de_env,rec=numero_de_rec)
    users.append(user)

app = Flask(__name__)

# Create an instance of your Server class
HOST = '127.0.0.1'  # Endereço IP local
PORT = 12345        # Porta a ser utilizada

SECRET_KEY = os.urandom(32)
JWE_SECRET = jwk.JWK(generate='oct', size=256)

def auth(encrypted_token):
    try:
        # Descriptografar o JWE para obter o JWT
        jwe_token = jwe.JWE()
        jwe_token.deserialize(encrypted_token, key=JWE_SECRET)
        token = jwe_token.payload.decode('utf-8')

        # Verificar e decodificar o JWS (JWT)
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded_token['sub'], 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 403
    except:
        return jsonify({'message': 'error token'}), 403
    
# Route to handle client registration
@app.route('/register', methods=['POST'])
def register_client():
    data = request.json
    uid,rmsg,codigo = request_message(data,private_key)
    if codigo != 200:
        print(f"Erro no request message:{codigo}")
        return jsonify({"error": codigo}), codigo
    
    user,codigo = new_client(uid,rmsg,users)
    if codigo == 200:
        users.append(user)
        print(f"Register feito com sucesso:{uid}")
    elif codigo == 201:
        print(f"Utilizador {uid} ja existe")
    else:
        print(f"Erro ao registar {uid}:{codigo},{user}")
        return jsonify({"error": codigo}), codigo
    
    payload = {
        'sub': uid,
        'iat': datetime.datetime.now(),
        'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    # Encriptar o JWT usando JWE
    jwe_token = jwe.JWE(plaintext=token.encode('utf-8'),
                            protected={'alg': 'A256KW', 'enc': 'A256CBC-HS512'})
    jwe_token.add_recipient(JWE_SECRET)
    encrypted_token = jwe_token.serialize()

    return jsonify({"message": "Message received successfully",'token': encrypted_token}), 200

# Route to handle receiving messages
@app.route('/message', methods=['GET','POST'])
def handle_message():
    uid,code = auth(request.headers.get('Authorization')) 
    if code != 200:
        return uid
    if request.method == 'GET':
        rmsg = request.args.get('message')
        rmsg_sign = request.args.get('msgSign')
        uid,rmsg,codigo = request_message({'message':rmsg,'msgSign':rmsg_sign},private_key)
        if codigo != 200:
            print(f"Erro no request message:{codigo}")
            return jsonify({"error": codigo}), codigo
        
        key_client = get_chave(uid)
        if key_client == -1:
            print(f"Erro no request da chave publica do utilizador:{uid}")
            return jsonify({"error": "Key not found"}), 404
        
        valid = rmsg.decrypt_content(private_key,key_client)
        if valid == -1:
            print("Erro ao validar assinatura")
            return jsonify({"error": "Assinatura nao respondente"}), 420
        
        message, codigo = get_message(uid,rmsg,users,private_key,certificate)
        if codigo == 404:
            print(f"Erro nao foi encontrada a mensagem:{rmsg.content} do utilizador {uid}")
            return jsonify({"error": codigo}), codigo
        if codigo != 200:
            print(f"Erro {codigo}")
            return jsonify({"error": codigo}), codigo
        else:
            return message , 200
    elif request.method == 'POST':
        data = request.json
        uid,rmsg,codigo = request_message(data,private_key)
        if codigo != 200:
            print(f"Erro no request message:{codigo}")
            return jsonify({"error": codigo}), codigo
        
        codigo = receive(rmsg,data,users)
        return jsonify({"message": "Message received successfully"}), codigo

@app.route('/queue', methods=['GET'])
def handler_queue():
    uid,code = auth(request.headers.get('Authorization')) 
    if code != 200:
        return uid,code
    rmsg = request.args.get('message')
    rmsg_sign = request.args.get('msgSign')
    uid,rmsg,codigo = request_message({'message':rmsg,'msgSign':rmsg_sign},private_key)
    if codigo != 200:
        print(f"Erro no request message:{codigo}")
        return jsonify({"error": codigo}), codigo
    
    cypher,codigo = queue(uid,rmsg,certificate,private_key)
    return cypher,codigo

@app.route('/key', methods=['GET'])
def get_key():
    uid,code = auth(request.headers.get('Authorization')) 
    if code != 200:
        return uid
    rmsg = request.args.get('message')
    rmsg_sign = request.args.get('msgSign')
    uid,rmsg,codigo = request_message({'message':rmsg,'msgSign':rmsg_sign},private_key)
    if codigo != 200:
        print(f"Erro no request message:{codigo}")
        return jsonify({"error": codigo}), codigo
    
    key_client = get_chave(uid)
    if key_client == -1:
        print(f"Erro no request da chave publica do utilizador:{uid}")
        return jsonify({"error": "Key not found"}), 404
    
    rmsg.decrypt_content(private_key,key_client)
    key_asked = get_chave(rmsg.content)
    if key_asked == -1:
        print(f"Erro no request da chave publica do utilizador:{rmsg.content}")
        return jsonify({"error": "Key not found"}), 404

    msg = message('server',uid, 'server',uid, certificate, "ask_4_pk", key_asked)
    msg.serialize_public_key()
    msg.encrypt_content(key_client,private_key)
    serialized_msg = msg.serialize(key_client, private_key)

    return jsonify(serialized_msg),200

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=True)
