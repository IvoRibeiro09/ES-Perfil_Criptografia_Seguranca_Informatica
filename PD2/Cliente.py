import requests
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from message import *


def extract_public_key(cert):
    """Retorna a chave publica do certificado. 
    Entrada: caminho certificado, Saída: public_key"""
    with open(f"Auth_cert/{cert}", 'rb') as file:
        file_data = file.read()
        cert = x509.load_pem_x509_certificate(file_data)
        public_key = cert.public_key()
        public_key_out = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_out = serialization.load_pem_public_key(public_key_out)
    return public_key_out
    
class Cliente:
    def __init__(self, uid, pk, sk, cert, ca):
        self.id = uid
        self.pk = pk
        self.sk = sk
        self.cert = cert
        self.ca = ca
        self.base_url = 'http://127.0.0.1:12345'
        self.pks = {"server": extract_public_key('SERVER.crt')}
        self.help = """\nOpções:
1- Enviar Mensagem!
2- Ver mensagens não lidas!
3- Pedir mensagem!
4- Rever mensagens já lidas!
9- Fechar aplicação!\n"""
        self.register()

    def register(self):
        public_key_server = self.pks['server']
        msg = message(self.id, "server",self.id, "server",self.ca, "register", self.pk)
        msg.serialize_public_key()
        msg.encrypt_content(public_key_server,self.sk)
        serialized_msg = msg.serialize(public_key_server, self.sk)
        
        response = requests.post(f'{self.base_url}/register', json=serialized_msg)
        print(response)
        if response.status_code == 200:
            rmsg= response.json()
            self.token = rmsg['token']
            self.menu()

    def menu(self):
        option = int(input(self.help))
        while option != 9:
            if option == 1:
                print("\n#####################################################################")
                rid = input("Destinatário (Reciever): ")
                subj = input("Assunto (Subject): ")
                msg = input("Mensagem (Content): ")
                print("#####################################################################\n")
                # saber se conheço o rid
                # se sim 
                # se não pedir ao server
                if rid not in self.pks.keys():
                    if self.ask_4_pk(rid) == 0:
                        self.send_message(rid, subj, msg)
                    else:
                        print("MSG Serviço: Destinatŕio inválido!\n(MSG SERVICE: unknown user!)")
                else:
                    self.send_message(rid, subj, msg)
            elif option == 2:
                self.ask_queue("2")
            elif option == 4:
                self.ask_queue("5")
            elif option == 3:
                num = input("Qual o ID da mensagem que queres receber: \n(What is the ID of the message you want to receive)\n")
                self.get_message(num)
            option = int(input(self.help))
        
    def send_message(self, rid, subject, content):
        """Verifica se a mensagem possui menos de 1000 bytes.
        Assina, cifra, serializa e envia as mensagens ao server"""
        # Verificar tamanho do conteúdo menor que 1000 bytes
        message_bytes = content.encode('utf-8')
        if len(message_bytes) > 1000:
            return print('A mensagem excedeu os 1000 bytes')

        # Cifrar conteúdo. 1 para o servidor receber a mensagem.
        msg = message(self.id,"server",self.id,rid, self.ca, subject, content)
        # encriptar o conteudo
        msg.encrypt_content(self.pks[rid],self.sk)
        # Serializar a mensagem
        serialized_msg = msg.serialize(self.pks['server'], self.sk)
        
        headers = {
            "Authorization": f"{self.token}"
        }
        print('Mensagem enviada!(Message sent!)')  
        response = requests.post(f'{self.base_url}/message', json=serialized_msg, headers=headers)
        if response.status_code != 200:
            print(response.json())
            return -1
        print(response)

    def ask_4_pk(self, rid):
        public_key_server = self.pks['server']
        msg = message(self.id, 'server',self.id, 'server', self.ca, "ask_4_pk", rid)
        # Serializar a mensagem
        msg.encrypt_content(public_key_server,self.sk)
        serialized_msg = msg.serialize(public_key_server, self.sk)
        
        headers = {
            "Authorization": f"{self.token}"
        }
        response = requests.get(f'{self.base_url}/key', params=serialized_msg, headers=headers)
        print(response)
        if response.status_code != 200:
            print(response.json())
            return -1
        # receber chave
        recieved_message = response.json()
        #dá serealize da chave
        rmsg = message()
        valid = rmsg.deserialize(recieved_message, self.sk)
        if valid == -1:
            print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
            return -1
        if "unknown" not in rmsg.content:
            valid = rmsg.decrypt_content(self.sk,self.pks['server'])
            if valid == -1:
                print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
                return -1
            self.pks[rid] = rmsg.deserialize_public_key()
            #print("Chave do {} recebida!".format(rid))
            return 0
        return -1
    
    def ask_queue(self, type):
        public_key_server = self.pks['server']
        msg = message(self.id, "server", self.id, "server", self.ca, "",str(type))
        msg.encrypt_content(public_key_server,self.sk)
        serialized_msg = msg.serialize(public_key_server, self.sk)

        headers = {
            "Authorization": f"{self.token}"
        }
        response = requests.get(f'{self.base_url}/queue', params=serialized_msg, headers=headers)
        print(response)

        if response.status_code != 200:
            print(response.json())
            return -1
        #print('Pedido de lista enviado!')
        recieved_message = response.json()
        rmsg = message()
        valid = rmsg.deserialize(recieved_message, self.sk)
        if valid == -1:
            print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
            return -1
        
        valid = rmsg.decrypt_content(self.sk,public_key_server)
        if valid == -1:
            print("MSG Serviço: Erro na verificação da assinatura!\n(MSG SERVICE: verification error!)")
            return -1
        print(rmsg.content)
        return 0

    def get_message(self, num):
        public_key_server = self.pks['server']
        msg = message(self.id, "server",self.id, "server", self.ca, "ask_msg", num)
        msg.encrypt_content(public_key_server,self.sk)
        serialized_msg = msg.serialize(public_key_server, self.sk)
        # Envia msg
        headers = {
            "Authorization": f"{self.token}"
        }
        response = requests.get(f'{self.base_url}/message', params=serialized_msg, headers=headers)
        print(response)
        if response.status_code == 404:
            print("Nao foi encontrada a mensagem")
            return -1
        
        if response.status_code != 200:
            print(response.json())
            return -1
        # Receber mensagem
        serialized_message = response.json()
        # Decerializar a mensagem 
        rmsg = message()
        valid = rmsg.deserialize(serialized_message, self.sk)
        if valid == -1:
            print("MSG Serviço: Erro na verificação da assinatura da mensagem!\n(MSG SERVICE: verification error!)")
            return -1
        if rmsg.initialEmissor not in self.pks.keys():
            self.ask_4_pk(rmsg.initialEmissor)

        valida = rmsg.decrypt_content(self.sk,self.pks[rmsg.initialEmissor])
        if valida == -1:
            print("MSG Serviço: Erro na verificação da assinatura do conteudo!\n(MSG SERVICE: verification error!)")
            return -1
        if "MSG SERVICE: unknown message!" in rmsg.content:
            print("MSG Serviço: Não existe nenhuma mensagem com esse ID no servidor!\n(MSG SERVICE: unknown message ID!)")
        else:
            print("\n#####################################################################")
            print("Remetente (Sender): {}\nAssunto (Subject): {}\nMensagem (Content): {}".format(rmsg.initialEmissor, rmsg.subject, rmsg.content))
            print("#####################################################################\n")
        return 0
    
        
def login(password=None):
    # Solicitar nome de usuário e senha ao usuário
    nome = input("Nome de usuário: ")
    senha = input("Certificado (inserir o nome do ficheiro com terminação .crt): ")
    with open(f"Auth_cert/{senha}.p12", "rb") as file:
        p12_data = file.read()
    private_key, user_ca, _ = pkcs12.load_key_and_certificates(p12_data, password)
    public_key = private_key.public_key()
    return Cliente(nome, public_key, private_key, senha, user_ca)


cliente = login()