import importlib, importlib.util
import hashlib
import secrets
import string
import random
import sqlite3
from datetime import datetime

def module_from_file(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
RC = module_from_file("RC", "./RC.py")
AS = module_from_file("AS", "./AS.py")


class user_reg:
    IDu = ''
    PWu = ''
    ru = str(random.randint(1,17))
    
    def __init__(self):
        self.IDu = input("Enter an ID you choose: ")
        self.PWu = input("Enter passcode: ")
        now = datetime.now()
        t1 = datetime.timestamp(now)
        self.J = self.process(self.IDu, self.PWu, self.ru)
        #print(self.J)
        now = datetime.now()
        t2 = datetime.timestamp(now)
        print('User registration time taken is:   ', t2-t1)
    def process(self, IDu, PWu, ru):
        BIOu = int(input("Enter your BIO: "))
        a = IDu + ru
        b = PWu + ru
        PIDu = self.hash_sha(a)
        #print('PID', PIDu)
        PWDu = self.hash_sha(b)
        #print('PWD', PWDu)
        rC = RC.class_RC()
        P = rC.P
        SmartCard, Ws = rC.new_user(PIDu, PWDu)
        #print('Ws', Ws)
        Xs = int(Ws, 16) ^ int(PWDu, 16)
        Cu = self.hash_sha(IDu+Ws)
        
        SIGu, THETAu = BIOu*2, BIOu*3
        Vu = int(ru) ^ int(self.hash_sha(str(SIGu)), 16)
        h_ask = self.hash_sha(rC.ASK)
        conn = sqlite3.connect('database.sqlite')
        cursor=conn.cursor()
        conn.execute('insert into smart_card values (?,?,?,?,?,?,?,?,?)',(
            str(SmartCard), str(BIOu), str(Xs), str(Vu), str(Cu), str(THETAu), str(P[0]), str(P[1]), str(h_ask)))
        conn.commit()
        conn.close()
        return (str(SmartCard), str(BIOu), str(Xs), str(Vu), str(Cu), str(THETAu), str(P[0]), str(P[1]), str(h_ask))
        
    def hash_sha(self,s):
        h = hashlib.sha256(s.encode())
        return h.hexdigest()


class user_login:
    def __init__(self):
        self.IDu = input("Enter ID: ")
        self.PWu = input("Enter passcode: ")
        self.SCu = input("Insert Smart Card: ")
        now = datetime.now()
        self.t1 = datetime.timestamp(now)
        self.J = self.process()
        now = datetime.now()
        self.t2 = datetime.timestamp(now)
        print('time taken for authentication is   :', self.t2 - self.t3 )
    def process(self):
        conn = sqlite3.connect('database.sqlite')
        cursor=conn.cursor()
        cursor.execute('select * from smart_card where smart_card_no=(?)', (self.SCu,) )
        bio_and_others = cursor.fetchone()
        #print(bio_and_others)
        rC = RC.class_RC()
        sigma = str(int(bio_and_others[1])*2)
        #print('sigma', sigma)
        Vu = int(bio_and_others[3])
        Xs = bio_and_others[2]
        ru = Vu ^ int(self.hash_sha(sigma), 16)
        #print('ru', ru)
        PIDu = self.hash_sha(self.IDu + str(ru))
        #print('pid', PIDu)
        PWDu = self.hash_sha(self.PWu + str(ru))
        #print('pwd', PWDu)
        Ws = int(Xs) ^ int(PWDu, 16)
        Ws = '{:x}'.format(Ws)
        #print('ws', Ws)
        Cu = bio_and_others[4]
        #print('Cu', Cu)
        Cu__ = self.hash_sha(self.IDu + Ws)
        #print('Cu__', Cu__)
        if Cu == Cu__:
            print('login Successful')
            now = datetime.now()
            self.t3 = datetime.timestamp(now)
            print('time taken for login is:   ', self.t3-self.t1)
            cursor.execute('select distinct SIDa from tu')
            SIDa = cursor.fetchall()
            print("Select a Server from below options")
            for i in range(len(SIDa)):
                print(i, ".   ", SIDa[i][0])
            sel_server = input('choose a number that indicates the server:  ')
            SIDa = SIDa[int(sel_server)][0]
            print('SID selected:   ',SIDa)
            cursor.execute('select Rs from tu where SIDa=? and SmartCard=?',
                           (SIDa, self.SCu,) )
            Rs = cursor.fetchone()
            Rs = Rs[0]
            N1 = str(random.randint(1,17))
            alpha =str(rC.P[0]*int(N1))+ ' ' +str(rC.P[1]*int(N1))
            Qs = int(Rs) ^ int(PWDu, 16)
            Qs = '{:x}'.format(Qs)
            USK = rC.USK
            B_us = int(PIDu, 16) ^ int(self.hash_sha(SIDa + alpha + self.hash_sha(USK)), 16)
            B_us =  '{:x}'.format(B_us)
            D_us = self.hash_sha(PIDu + str(Qs) + alpha)

            #Mutual authen tication begins here
            
            aS = AS.class_AS()
            E_su, beta = aS.M1(B_us, D_us, alpha, SIDa)
            #print('E_su:   ',E_su)
            #print('beta:   ',beta)
            
            #phase 2 of mutual authentiction:
            beta_list = beta.split()
            K_su =str(int(beta_list[0])*int(N1))+str(int(beta_list[1])*int(N1)) 
            SK = self.hash_sha(Qs + K_su + PIDu)
            print('session key generated by user is:   ', SK)
            E_su__ = self.hash_sha(SK + SIDa + beta + alpha + Qs)
            
            if(E_su == E_su__):
                print('verified')
                F_us = self.hash_sha(SIDa +alpha+ beta + SK +Qs)
                #phase 3 of mutual authentiction:
                c = aS.M3(F_us)
                
        else:
            print('login failed due to wrong creds')
            now = datetime.now()
            self.t4 = datetime.timestamp(now)

        conn.close()
        return (Cu, self.hash_sha(self.IDu + str(Ws)))

    def hash_sha(self,s):
        h = hashlib.sha256(s.encode())
        return h.hexdigest()


if input("Press L for Login and R for registration:    ")=='L':
    x = user_login()
else:
    x = user_reg()
    print('here is your smartcard:   ', x.J[0])
    




























































