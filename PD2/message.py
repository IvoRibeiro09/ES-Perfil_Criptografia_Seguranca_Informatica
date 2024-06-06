import base64
import json
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# todas as msg tens de ser enviadas com o certificado do autor
# gerar um par de chaves em ambos os clientes
# passar a chave publica ao servidor com o certificado do mesmo
# encriptar o content com um algotitmo entre a private key e chave publica do outro
# encriptar a message com um algoritmo que o server consiga decifrar


def escape_special_characters(string):
    # Função para escapar caracteres especiais
    escaped_string = string.replace('"', '\\"')  # Escapar aspas duplas
    escaped_string = string.replace('./', 'exec ')  # Escapar aspas duplas
    # Adicione mais substituições de caracteres especiais, se necessário
    return escaped_string

def encrypt(plaintext, receiverPK):
    # Gerar uma chave AES aleatória
    aes_key = os.urandom(32)  # 32 bytes = 256 bits
    iv = os.urandom(16)  # 16 bytes = 128 bits
    # Criptografar os dados com a chave AES
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Criptografar a chave AES com a chave pública RSA do destinatário
    encrypted_aes_key = receiverPK.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Obter o tag de autenticação
    authentication_tag = encryptor.tag
    ciphertextmsg = base64.b64encode(encrypted_aes_key 
                            + iv
                            + authentication_tag
                            + ciphertext
                            )
    return ciphertextmsg

def decrypt(encrypted_data, receiver_sk):
    # Decodificar os dados criptografados da base64
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    # Extrair a chave AES criptografada e o texto cifrado
    encrypted_aes_key = encrypted_data_bytes[:256]  # Tamanho da chave RSA OAEP
    iv = encrypted_data_bytes[256:272]
    tag = encrypted_data_bytes[272:288]
    ciphertext = encrypted_data_bytes[288:]
    # Descriptografar a chave AES com a chave privada RSA do destinatário
    aes_key = receiver_sk.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decifrar os dados usando a chave AES e o IV
    # Inicializar o objeto decryptor com o IV e o tag de autenticação
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    # Descriptografar os dados
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def Sign(content, key):
    signature = key.sign(
        content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def Verify(signature, recieved_message, sender_pk):
    signature_bytes = base64.b64decode(signature)
    try:
        sender_pk.verify(
            signature_bytes,
            recieved_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return 1
    except:
        return -1
        
class message:
    def __init__(self, sID=None, rID=None, initial=None, final=None, ca=None, s=None, c=None):
        if all(arg is None for arg in (sID, initial, final, ca, rID, s, c)):
            # If all arguments are None, set default values
            self.senderID = None
            self.reciverID = None
            self.initialEmissor = None
            self.finalReciever = None
            self.senderCA = None
            self.subject = None
            self.content = None
            self.contentsign = None
        else:
            # Initialize with provided arguments
            self.senderID = sID
            self.reciverID = rID
            self.initialEmissor = initial
            self.finalReciever = final
            self.senderCA = ca
            self.subject = s
            self.content = c
            self.contentsign = None
    
    def generate(self):
        message = {
            'SenderID': self.senderID,
            'ReceiverID': self.reciverID,
            'InitialEmissor': self.initialEmissor,
            'FinalReciever': self.finalReciever,
            'senderCA': self.senderCA,
            'Subject': self.subject,
            'Content': self.content,
            'ContentSign': self.contentsign
        }
        return message
    
    def build(self, message_dict):
        self.senderID = message_dict['SenderID']
        self.reciverID = message_dict['ReceiverID']
        self.initialEmissor = message_dict['InitialEmissor']
        self.finalReciever = message_dict['FinalReciever']
        self.senderCA = message_dict['senderCA']
        self.subject = message_dict['Subject']
        self.content = message_dict['Content']
        self.contentsign = message_dict['ContentSign']
    
    #limitado a 1000 bytes
    def JSONinjectionValidation(self):
        i = 0
        for item in [self.senderID, self.reciverID, self.initialEmissor, self.finalReciever, self.senderCA, self.subject, self.content, self.contentsign]:
            if not isinstance(item, str):
                print(item,i)
                raise ValueError("Todos os argumentos devem ser strings")
            i+=1
            item = escape_special_characters(item)
    
    def encrypt_content(self, contentReceiverPK, private_key):
        # Assinatura do content
        self.contentsign = Sign(self.content.encode('utf-8'), private_key)
        # Encriptação do conteudo
        self.content = encrypt(self.content.encode('utf-8'), contentReceiverPK).decode('utf-8')

    def decrypt_content(self, mySK, sender_pk):
        try:
            self.content = decrypt(self.content.encode('utf-8'), mySK).decode('utf-8')
            valid = Verify(self.contentsign.encode('utf-8'), self.content.encode('utf-8'), sender_pk)
            return valid
        except:
            return -1
        
    def serialize(self, server_pk, private_key):
        self.content = encrypt(self.content.encode('utf-8'), server_pk).decode('utf-8')
        self.senderCA = self.senderCA.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        self.JSONinjectionValidation()
        msg = self.generate()
        serialized_msg = json.dumps(msg)
        # encrypt do msg_bytes
        msg_bytes = base64.b64encode(serialized_msg.encode('utf-8'))
        # msg_bytes = serialized_msg.encode('utf-8')
        cipher = encrypt(msg_bytes, server_pk)
        # Assinatura da mensagem
        msgSign = Sign(cipher, private_key)
        # concatenar a assinatura com a cifra
        return {'message':cipher.decode('utf-8'),'msgSign':msgSign}

    def deserialize(self, cipher, mySK):
        msgsign = cipher['msgSign']
        cipher_msg = cipher['message'].encode('utf-8')
        #decrypt da mensagem 
        msg_bytes = decrypt(cipher_msg, mySK)
        #Convert to JSON
        serialized_msg = base64.b64decode(msg_bytes.decode('utf-8'))
        message_dict = json.loads(serialized_msg)
        # Atribuir os valores do dicionário aos atributos 'self'
        self.build(message_dict)
        # Verificar JSON injection
        self.JSONinjectionValidation()
        self.senderCA = x509.load_pem_x509_certificate(self.senderCA.encode('utf-8'), default_backend())
        sender_pk = self.senderCA.public_key()
        self.content = decrypt(self.content.encode('utf-8'), mySK).decode('utf-8')
        return Verify(msgsign, cipher_msg, sender_pk)
    
    def print(self):
        print("Message:")
        print("  Sender ID: ", self.senderID)
        print("  Receiver ID: ", self.reciverID)
        print("  Initial Emissor: ", self.initialEmissor)
        print("  Final Reciever: ", self.finalReciever)
        print("  Sender CA: ", self.senderCA)
        print("  Subject: ", self.subject)
        print("  Content: ", self.content)
        print("  Content Signature: ", self.contentsign)
        print("------------------------------------------------------")
    
    def serialize_public_key(self):
        serialized_key = self.content.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.content = serialized_key.decode('utf-8')

    def deserialize_public_key(self):
        pem_bytes = self.content.encode('utf-8')
        return  serialization.load_pem_public_key(pem_bytes, backend=default_backend())
