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
RC = module_from_file("RC_old", "./RC_old.py")

class user_reg:
    IDi = ''
    PWi = ''
    ru = str(random.randint(1,17))
    
    def __init__(self):
        self.IDi = input("Enter an ID you choose: ")
        self.PWi = input("Enter passcode: ")
        now = datetime.now()
        t1 = datetime.timestamp(now)
        self.J = self.process(self.IDi, self.PWi)
        now = datetime.now()
        t2 = datetime.timestamp(now)
        print('User registration time taken is:   ', t2-t1)
        
    def process(self, IDi, PWi):
        BIOi = int(input("Enter your BIO: "))
        rC = RC.class_RC()
        
        Ri, Pi = BIOi*2, BIOi*3
        RPWi = self.hash_sha(self.PWi + str(Ri))
        #print('RPWi', RPWi)
        Bi, Ci, Di, Vi = rC.user_reg(self.IDi, RPWi)
        conn = sqlite3.connect('database.sqlite')
        cursor1=conn.cursor()
        cursor1.execute('Select * from smartcardold')
        tu = cursor1.fetchall()
        #print(tu)
        #print(tu, 'tu')
        smartcardno = 0
        if len(tu)==0:
            smartcardno = 100001
        else:
            z = int(tu[len(tu)-1][0])+1
            smartcardno = str(int(z)+1)
        print('your smart card number:  ' , smartcardno)
        conn.execute( 'insert into smartcardold values (?,?,?,?,?,?,?,?,?)', (
            smartcardno, IDi, '1', BIOi ,str(Bi),str(Ci), str(Di), str(Vi), str(Pi)) )
        conn.commit()
        conn.close()
        return (smartcardno, IDi, '1',str(BIOi) , str(Bi),str(Ci), str(Di), str(Vi), str(Pi))
        
    def hash_sha(self,s):
        h = hashlib.sha256(s.encode())
        return h.hexdigest()
    

'''
x = user_reg()
print(x.J)
'''


class user_login:
    def __init__(self):
        self.IDi = input("Enter ID: ")
        self.PWi = input("Enter passcode: ")
        self.SCi = input("Insert Smart Card: ")
        now = datetime.now()
        self.t1 = datetime.timestamp(now)
        self.process()
        now = datetime.now()
        self.t2 = datetime.timestamp(now)
        print('time taken for authentication is   :', self.t2 - self.t3 )
        
    def process(self):
        conn = sqlite3.connect('database.sqlite')
        cursor=conn.cursor()
        cursor.execute('select * from smartcardold where smart_card_no=(?)', (self.SCi,) )
        db_vals = cursor.fetchone()
        Ri = int(db_vals[3])*2
        RPWi = self.hash_sha(self.PWi + str(Ri))
        Vi__ = self.hash_sha(self.IDi + RPWi)
        Vi = db_vals[7]
        if(Vi == Vi__):
            print('LOGIN SUCCESFUL')
            now = datetime.now()
            self.t3 = datetime.timestamp(now)
            print('time taken for login is:   ', self.t3-self.t1)
            N1 = str(random.randint(1,100))
            Bi = db_vals[4]
            Ci = db_vals[5]
            h_PSK = int(Bi) ^ int(Ci)
            h_PSK = '{:x}'.format(h_PSK)
            AIDi = int(self.hash_sha(self.IDi), 16) ^ int(self.hash_sha(N1), 16)
            M1 = int(RPWi, 16) ^ int(N1) ^ int(h_PSK,16)
            #
            cursor.execute('select distinct SID from ts_old')
            SIDa = cursor.fetchall()
            print("Select a Server from below options")
            for i in range(len(SIDa)):
                print(i, ".   ", SIDa[i][0])
            sel_server = input('choose a number that indicates the server:   ')
            SIDa = SIDa[int(sel_server)][0]
            print('SID selected:   ',SIDa)
            #
            
            
            rC = RC.class_AS()
            now = datetime.now()
            timestamp = datetime.timestamp(now)
            Ti = str(timestamp)
            Di = db_vals[6]
            M2 = self.hash_sha(str(AIDi) + N1 + RPWi + SIDa+ Ti)

            #mutual authentication begins
            
            M3, M4 = rC.MA1(AIDi, M1, M2, Bi, Di, Ti, SIDa, N1)

            #phase of MA
            N2 = M3 ^ int(self.hash_sha(str(AIDi) + N1), 16) ^ int(h_PSK, 16)
            SK = self.hash_sha(str(AIDi) + SIDa + N1 + str(N2))
            print('session genrated by the user:  ', SK)
            M4__ = self.hash_sha(SIDa + str(N2) + str(AIDi))
            if(M4 == M4__):
                #print('M2 done')
                M5 = self.hash_sha(SK + N1 + str(N2))
                #phase of MA
                rC.MA3(M5)        

        else:
            print('login failed')
            exit
        conn.close()
        return 

    def hash_sha(self,s):
        h = hashlib.sha256(s.encode())
        return h.hexdigest()


if input("Press L for Login and R for registration:    ")=='L':
    x = user_login()
else:
    x = user_reg()
    




























































