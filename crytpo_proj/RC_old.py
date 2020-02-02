import importlib, importlib.util
import hashlib
import secrets
import string
import sqlite3
import random
from datetime import datetime

    

class class_RC:
    #hash function : SHA256
    def hash_sha(self, s):
        h = hashlib.sha256(s.encode())
        return h.hexdigest()
    
    def on_AS(self, SIDa, PSK):
        conn = sqlite3.connect('database.sqlite')
        cursor=conn.cursor()
        cursor.execute("insert into ts_old values (?,?)", (SIDa,PSK))
        conn.commit()
        conn.close()
        
    def user_reg(self, IDi, RPWi):
        now = datetime.now()
        timestamp = datetime.timestamp(now)
        Ts = str(timestamp)
        #print('Ts    ', Ts )
        Ai = self.hash_sha(IDi + '4' + Ts)
        #print('Ai ', Ai)
        Bi = int(RPWi, 16) ^ int(self.hash_sha(Ai), 16)
        #print('Bi  ', Bi)
        AS = class_AS() 
        h_PSK = self.hash_sha(AS.PSK)
        #print('h-psk  ', h_PSK)
        Ci = Bi ^ int(h_PSK, 16)
        #print('Ci   ', Ci)
        Di = int(AS.PSK) ^  int(Ai, 16) ^ int (h_PSK, 16)
        #print('Di ', Di)
        Vi = self.hash_sha(IDi + RPWi)
        #print('Vi', Vi)
        return Bi, Ci, Di, Vi


class class_AS: 

    SIDa = ''.join(secrets.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase)
                                                  for i in range(8))

    PSK = '12345678'
    def create_server(self):
        now = datetime.now()
        t1 = datetime.timestamp(now)
        rc = class_RC()
        rc.on_AS(self.SIDa, self.PSK)
        now = datetime.now()
        t2 = datetime.timestamp(now)
        print('time to create server:   ', t2-t1)
    
    def hash_sha(self, s):
        h = hashlib.sha256(s.encode())
        return h.hexdigest()
    #h_PSK = hash_sha(PSK)

    def MA1(self, AIDi, M1, M2, Bi, Di, Ti, SIDj, N1):
        self.h_PSK = self.hash_sha(self.PSK )
        now = datetime.now()
        self.N1 = N1
        timestamp = datetime.timestamp(now)
        Tj = str(timestamp)
        if (float(Ti)- float(Tj)<3.5):
            Ai = int(self.PSK ) ^ int(Di) ^ int(self.h_PSK, 16)
            Ai = '{:x}'.format(Ai)
            RPWi = int(Bi) ^ int(self.hash_sha(Ai), 16)
            RPWi = '{:x}'.format(RPWi)
            N1 = str(int(RPWi, 16) ^ M1 ^ int(self.h_PSK,16))
            M2__ = self.hash_sha(str(AIDi) + N1+ str(RPWi) + SIDj + Ti)
            if(M2 == M2__):
                self.N2 = str(random.randint(1,100))
                self.SK = self.hash_sha(str(AIDi) + SIDj + N1 + self.N2)
                print('session key in server:  ', self.SK)
                self.M3 = int(self.N2) ^ int(self.hash_sha(str(AIDi) + N1), 16) ^ int(self.h_PSK, 16)
                self.M4 = self.hash_sha(SIDj + self.N2 + str(AIDi))
                return self.M3, self.M4
            else:
                print('M1 failed')
                return self.M3, self.M4
        else:
            print('time problwm')
            return self.M3, self.M4

    def MA3(self, M5):
        M5__ = self.hash_sha(self.SK + self.N1 + self.N2)
        if(M5 == M5__):
            print('MUTUAL AUTHENTICATION SUCCESS')
        else:
            print('MUT auth fail')

'''

x = class_AS()
x.create_server()

'''



    
