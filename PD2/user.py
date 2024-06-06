import os,json

class User:
    def __init__(self,uid,env=0,rec=0):
        self.uid = uid
        self.number_env = env
        self.number_rec = rec
        if not os.path.exists(f"server/{uid}"):
            os.makedirs(f"server/{uid}")
        if not os.path.exists(f"server/{uid}/rec"):
            os.makedirs(f"server/{uid}/rec")
        if not os.path.exists(f"server/{uid}/env"):
            os.makedirs(f"server/{uid}/env")

    def add_send_message(self,uid,cypher):
        assert self.uid == uid, "Nao tem permissoes para escrever neste user"
        
        with open(f"server/{uid}/env/{self.number_env}.json", "w") as f:
            json.dump(cypher,f)
        self.number_env+=1

    def add_message(self,uid,cypher):
        assert self.uid == uid, "Nao tem permissoes para escrever neste user"

        with open(f"server/{uid}/rec/{self.number_rec}.json", "w") as f:
            json.dump(cypher,f)
        self.number_rec+=1
    
    def get_message(self,uid,number):
        assert self.uid == uid, "Nao tem permissoes para escrever neste user"
        
        with open(f"server/{uid}/rec/{number}.json", "r") as f:
            m = json.load(f)

        return m

    def get_uid(self):
        return self.uid