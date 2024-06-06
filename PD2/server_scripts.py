import datetime
from cryptography.hazmat.primitives import serialization
import cryptography.x509.oid as oid
from message import * 
import os
import csv
from user import *

def request_message(data,sk):
    mensagem_rec = message()
    valid = mensagem_rec.deserialize(data, sk)
                   
    if valid == -1:
        print("MSG SERVICE: verification error!")
        return None,None,400
    
    for attribute in mensagem_rec.senderCA.subject:
        if attribute.oid == oid.NameOID.PSEUDONYM:
            uid = attribute.value
            break
    
    if uid != mensagem_rec.senderID:
        return None,None,403

    return uid,mensagem_rec,200

def new_client(UID,mensagem_rec,users):
    try:
        user = get_user(UID,users)
        if user != None:
            return None,201        
        chave_recevida = mensagem_rec.senderCA.public_key()
        chave_recevida = chave_recevida.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        cl = User(UID)
        
        with open(f"server/pks/{UID}.pk", "wb+") as f:
            f.write(chave_recevida)
        
        return cl,200
    except Exception as e:
        return e,500

def get_user(UID,users):
    for user in users:
        if user.get_uid() == UID:
            return user
        
def receive(message,cypher,users):
    Uid = message.finalReciever
    sender_id = message.senderID
    user = get_user(Uid,users)
    user.add_message(Uid,cypher)
    
    sender = get_user(sender_id,users)
    sender.add_send_message(sender_id,cypher)
    with open("server/log.csv", mode='a+', newline='') as arquivo_csv:
        escritor_csv = csv.writer(arquivo_csv)
        linha = [str(user.number_rec-1),sender_id,str(datetime.datetime.now()),message.subject,Uid,"FALSE"]
        escritor_csv.writerow(linha)

    return 200

def queue (UID,rmsg,certificate,private_key):
    chave_recetor = get_chave(UID)
    rmsg.decrypt_content(private_key,chave_recetor)
    type = rmsg.content

    dados = []
    if type == '2':
        lida = 'FALSE'
    else:
        lida = 'TRUE'
    with open("server/log.csv", mode='r', newline='') as arquivo_csv:
        leitor_csv = csv.reader(arquivo_csv)
        # Iterando sobre as linhas do arquivo CSV
        for linha in leitor_csv:
            if linha[4]==UID and linha[5] == lida:
                dados.append(linha)
    resposta = ""
    for linha in dados:
        resposta += "ID: " + linha[0] +", SENDER: "+ linha[1] + ", TIME: " + linha[2] + ", SUBJECT: " + linha[3] + "\n"
    if resposta == "":
        resposta = "\nNão tem nenhuma mensagem por ler no servidor!\n(There are no unread messages on the server!)\n"

    msg = message("server",UID,"server",UID, certificate, "", resposta)
    msg.encrypt_content(chave_recetor,private_key)
    cypher = msg.serialize(chave_recetor,private_key)
    return cypher , 200

def get_message(UID, mensagem_rec,users,private_key,certificate):
    number = mensagem_rec.content
    # recoperar a cifra guardada
    existe = False
    with open("server/log.csv", mode='r', newline='') as arquivo_csv:
        leitor_csv = csv.reader(arquivo_csv)
        linhas = list(leitor_csv)
    for linha in linhas:
        if linha[0] == str(number) and linha[4] == UID:
            linha[5]= "TRUE"
            existe = True
            break
    # Escrever o conteúdo modificado de volta para o arquivo
    with open("server/log.csv", mode='w', newline='') as arquivo_csv:
        escritor_csv = csv.writer(arquivo_csv)
        escritor_csv.writerows(linhas)

    if existe:
        chave_recetor = get_chave(UID)
        aux_msg = message()
        user = get_user(UID,users)
        ciphertext_guardada = user.get_message(UID, number)    
        verify = aux_msg.deserialize(ciphertext_guardada, private_key)
        if verify == -1:
            return None,420
        aux_msg.senderID = 'server'
        aux_msg.reciverID = UID
        aux_msg.senderCA = certificate
        cipher = aux_msg.serialize(chave_recetor, private_key)

        return cipher,200
    else:
        return None,404

def get_chave (UID):
    if not os.path.exists(f"server/pks/{UID}.pk"):
        return -1
    with open(f"server/pks/{UID}.pk", "rb") as key_file:
        pk = serialization.load_pem_public_key(key_file.read())
    return pk