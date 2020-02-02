import importlib, importlib.util
from tinyec.ec import SubGroup, Curve
import hashlib
import secrets
import string
import sqlite3


class class_RC:
    P = (15, 13)
    #defining elliptical curve, selecting a base point
    field = SubGroup(p=17, g=(15, 13), n=18, h=1)
    curve = Curve(a=0, b=7, field=field, name='elliptic_curve')
    #setting fixed ASK and USK
    ASK = 'J1BI6av3'
    USK = '6VWxi48Q'
    #hash function : SHA256
    def hash_sha(self, s):
        h = hashlib.sha256(s.encode())
        return h.hexdigest()
    #to create a server with SID 
    def on_AS(self, SIDa):
        SID_concat = SIDa + self.ASK
        Ks = self.hash_sha(SID_concat)
        h_ask = self.hash_sha(self.ASK)
        #insert into database
        conn = sqlite3.connect('database.sqlite')
        cursor=conn.cursor()
        cursor.execute("insert into TS values (?,?)", (SIDa, Ks))
        conn.commit()
        conn.close()

        return (Ks,h_ask, self.P)

    #to create a new user
    def new_user(self, PIDu, PWDu):
        conn = sqlite3.connect('database.sqlite')
        cursor=conn.cursor()
        cursor.execute('Select * from TS')
        ts = cursor.fetchall()
        conn.commit()
        length = len(ts)
        cursor1=conn.cursor()
        cursor1.execute('Select * from TU')
        tu = cursor1.fetchall()
        SmartCard = 0
        Ws = ''
        if len(tu)==0:
            SmartCard = 100001
        else:
            z = int(tu[len(tu)-1][1])+1
            SmartCard = int(z)+1
        for i in range(length):
            Qs = self.hash_sha(PIDu + ts[i][1])
            Rs = int(Qs, 16) ^ int(PWDu, 16)
            #table to be inserted into smartcard
            conn.execute('insert into tu values (?,?,?)', (ts[i][0],str(SmartCard), str(Rs)))
            conn.commit()
            Ws = self.hash_sha(PIDu + self.USK)
            h_ask = self.hash_sha(self.ASK)
            
        conn.close()
        return SmartCard, Ws











    
