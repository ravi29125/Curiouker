from django.shortcuts import render , HttpResponse
from django.contrib.auth import authenticate, login , logout
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from . import models

class Rotor:
    def __init__(self,wiring=None,notchs=None,state="A",ring="A",):
        if wiring != None:
            self.wiring = wiring
        else:
            self.wiring = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.rwiring = ["0"] * 26
        for i in range(0, len(self.wiring)):
            self.rwiring[ord(self.wiring[i]) - ord("A")] = chr(ord("A") + i)
        if notchs != None:
            self.notchs = notchs
        else:
            self.notchs = ""
        self.state = state
        self.ring = ring
    def __setattr__(self, name, value):
        self.__dict__[name] = value
        if name == "wiring":
            self.rwiring = ["0"] * 26
            for i in range(0, len(self.wiring)):
                self.rwiring[ord(self.wiring[i]) - ord("A")] = chr(ord("A") + i)
    def encipher_right(self, key):
        shift = ord(self.state) - ord(self.ring)
        index = (ord(key) - ord("A")) % 26
        index = (index + shift) % 26
        letter = self.wiring[index]
        out = chr(
            ord("A") + (ord(letter) - ord("A") + 26 - shift) % 26
        )
        return out
    def encipher_left(self, key):
        shift = ord(self.state) - ord(self.ring)
        index = (ord(key) - ord("A")) % 26
        index = (index + shift) % 26
        letter = self.rwiring[index]
        out = chr(ord("A") + (ord(letter) - ord("A") + 26 - shift) % 26)
        return out
    def notch(self, offset=1):
        self.state = chr((ord(self.state) + offset - ord("A")) % 26 + ord("A"))
        notchnext = self.state in self.notchs
    def is_in_turnover_pos(self):
        return chr((ord(self.state) + 1 - ord("A")) % 26 + ord("A")) in self.notchs
    def __eq__(self, rotor):
        return self.name == rotor.name
    def __str__(self):
        return """
        Wiring: {}
        State: {}""".format(self.name, self.model, self.date, self.wiring, self.state)

class Reflector:
    def __init__(self, wiring=None):
        if wiring != None:
            self.wiring = wiring
        else:
            self.wiring = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    def __setattr__(self, name, value):
        self.__dict__[name] = value
    def encipher(self, key):
        shift = ord(self.state) - ord("A")
        index = (ord(key) - ord("A")) % 26
        index = (index + shift) % 26
        letter = self.wiring[index]
        out = chr(ord("A") + (ord(letter) - ord("A") + 26 - shift) % 26)
        return out
    def __eq__(self, rotor):
        return self.name == rotor.name
    def __str__(self):
        return """
        Wiring: {}""".format(self.name, self.model, self.date, self.wiring)


# length controll
def createLength(given):
    num=16
    while(len(given)<num):
        given+=given[::-1]
    return given[:num][::-1]

# Generate plugins
def GenPlug(mess="EHOPQABVDWICJ"):
    import random
    message=""
    s="NXYZGRFTULMSK"
    cnt=0
    while(len(message)<16):
        num = random.randrange(1,len(s)-1)
        n=random.randrange(0,len(mess))
        if s[num] not in message and mess[n] not in message :
            message+=mess[n].upper()
            message+=s[num]
            if(len(message)<16):
                message+=' '
            else:
                break
    return message


# Random Key
def GenKey():
    import random
    message=""
    s="JPGVOUMFYQBENHZRDKASXLICTW"
    while(len(message)<3):
        num = random.randrange(1,len(s)-1)
        if s[num] not in message:
            message+=s[num]
    return message


def specialCharacteer():
    import random
    message=""
    n=8
    s =['!', '#', '$', '%', '&', '(', ')', '*', '+', ',', '-', '.', '/', ':',
            ';', '<', '=', '>', '?', '@', '[',']',
                '^', '_', '`', '{', '|', '}', '~']
    while(len(message)<n):
        num = random.randrange(1,len(s)-1)
        if s[num] not in message:
            message+=(s[num])
    return message


def number(given):
    num=0
    k=8
    for j in given:
        num+=ord(j)
    while(len(str(num))<k):
        num+=num
    return num


def Rotrt():
    import random
    message=[]
    s=[["FSOKANUERHMBTIYCWLQPZXVGJD"],["LEYJVCNIXWPBQMDRTAKZGFUHOS"],["FKQHTLXOCBJSPDZRAMEWNIUYGV","AN"],["NZJHGRCXMYSWBOUFAIVLPEKQDT","AN"],
    ["JPGVOUMFYQBENHZRDKASXLICTW","AN"],["VZBRGITYUPSDNHLXAWMJQOFECK","A"],["ESOVPZJAYQUIRHXLNFTGKDCMWB","K"],["BDFHJLCPRTXVZNYEIWGAKMUSQO","W"],
    ["AJDKSIRUXBLHWTMCQGZNPYFVOE","F"],["ABCDEFGHIJKLMNOPQRSTUVWXYZ"],["EKMFLGDQVZNTOWYHXUSPAIBRCJ","R"],["QWERTZUIOASDFGHJKPYXCVBNML"],["IMETCGFRAYSQBZXWLHKDVUPOJN"],
    ["EHRVXGAOBQUSIMZFLYNWKTPDJC"],["ZOUESYDKFWPCIQXHMVBLGNJRAT"],["PEZUOHXSCVFMTBGLRINQJWAYDK"],["QWERTZUIOASDFGHJKPYXCVBNML"],
    ["QYHOGNECVPUZTFDJAXWMKISRBL"],["JVIUBHTCDYAKEQZPOSGXNRMWFL"],["DMTWSILRUYQNKFEJCAZBPGXOHV"],["HQZGPJTMOBLNCIFDYAWVEUSRKX"],
    ["UQNTLSZFMREHDPXKIBVYGJCWOA"],["JGDQOXUSCAMIFRVTPNEWKBLZYH"],["NTZPSFBOKMWRCJDIVLAEYUXHGQ"]]
    while(len(message)<3):
        num = random.randrange(1,len(s)-1)
        if s[num] not in message:
            message.append(s[num])
    return message

def Reflact():
    import random
    s=[["EJMZALYXVBWFCRQUONTSPIKHGD"],["YRUHQSLDPXNGOKMIEBFZCWVJAT"],["FVPJIAOYEDRZXWGCTKUQSBNMHL"],
        ["ENKQAUYWJICOPBLMDXZVFTHRGS"],["RDOBJNTKVEHMLFCWZAXGYIPSUQ"]]
    num = random.randrange(1,len(s)-1)
    return s[num][0]


def Zconvert(s, numRows=4):
    if numRows == 1 or numRows >= len(s):
        return s
    result = [''] * numRows
    row, jump = 0, 1
    for char in s:
        result[row] += char
        if row == 0:
            jump = 1
        elif row == numRows - 1:
            jump = -1
        row += jump
    return ''.join(result)

'''c=createLength("Ravi")+str(number("Ravi"))+specialCharacteer()
print(Zconvert(c))'''

class Enigma:
    def __init__(self, ref, r1, r2, r3, key="AAA", plugs="", ring="AAA"):
        self.reflector = ref
        self.rotor1 = r1
        self.rotor2 = r2
        self.rotor3 = r3
        self.rotor1.state = key[0]
        self.rotor2.state = key[1]
        self.rotor3.state = key[2]
        self.rotor1.ring = ring[0]
        self.rotor2.ring = ring[1]
        self.rotor3.ring = ring[2]
        self.reflector.state = "A"
        plugboard_settings = [(elem[0], elem[1]) for elem in plugs.split()]
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        alpha_out = [" "] * 26
        for i in range(len(alpha)):
            alpha_out[i] = alpha[i]
        for k, v in plugboard_settings:
            alpha_out[ord(k) - ord("A")] = v
            alpha_out[ord(v) - ord("A")] = k
        try:
            self.transtab = str.maketrans(alpha, "".join(alpha_out))
        except:
            from string import maketrans
            self.transtab = maketrans(alpha, "".join(alpha_out))
    def encipher(self, plaintext_in):
        ciphertext = ""
        plaintext_in_upper = plaintext_in.upper()
        plaintext = plaintext_in_upper.translate(self.transtab)
        for c in plaintext:
            if not c.isalpha():
                ciphertext += c
                continue
            if self.rotor2.is_in_turnover_pos():
                self.rotor2.notch()
                self.rotor3.notch()
            if self.rotor1.is_in_turnover_pos():
                self.rotor2.notch()
            self.rotor1.notch()
            t = self.rotor1.encipher_right(c)
            t = self.rotor2.encipher_right(t)
            t = self.rotor3.encipher_right(t)
            t = self.reflector.encipher(t)
            t = self.rotor3.encipher_left(t)
            t = self.rotor2.encipher_left(t)
            t = self.rotor1.encipher_left(t)
            ciphertext += t
        res = ciphertext.translate(self.transtab)
        fres = ""
        for idx, char in enumerate(res):
            if plaintext_in[idx].islower():
                fres += char.lower()
            else:
                fres += char
        return fres
    def __str__(self):
        return """
        Reflector: {}
        Rotor 1: {}
        Rotor 2: {}
        Rotor 3: {}""".format(
            self.reflector, self.rotor1, self.rotor2, self.rotor3
        )


from django.contrib import messages

# Create your views here.
def loginpage(request):
    if request.method =='POST':
        users=request.POST.get('user')
        password=request.POST.get('password')
        user=authenticate(username=users,password=password)
        #print(users,password)
        if user is None:
            messages.error(request, 'User doesnot exist')
            return redirect('loginpage')
        else:
            login(request,user)
            return redirect('homepage')
    else:
        return render(request,'login.html')


def signinpage(request):
    if request.method=='POST':
        username=request.POST.get('username')
        name=request.POST.get('firstname')
        email=request.POST.get('email')
        password=request.POST.get('password')
        retype_password=request.POST.get('retype_password')
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists. Please choose a different username.')
            return redirect('loginpage')
        if password != retype_password:
            messages.error(request, 'Password is not matching')
            return redirect('loginpage')
        user=User.objects.create_user(username=username,email=email,password=password)
        user.first_name=name
        user.save()
        Ref=Reflact()
        rot=Rotrt()
        r1=rot[0][0]
        n1=None
        if len(rot[0])==2:
            n1=rot[0][1]
        r2=rot[1][0]
        n2=None
        if len(rot[1])==2:
            n2=rot[1][1]
        r3=rot[2][0]
        n3=None
        if len(rot[2])==2:
            n1=rot[2][1]
        specCh=specialCharacteer()
        keyo=GenKey()
        plugh=GenPlug()
        user_instance = User.objects.get(username=username)
        data=models.UserData(user_name=user_instance,plug=plugh,Reflactorr=Ref,Router1=r1,Router2=r2
                            ,Router3=r3,notch1=n1,notch2=n2,notch3=n3,key=keyo,ring=keyo[::-1],specialch=specCh)
        data.save()
        login(request,user)
        return redirect('homepage')
    else:
        return render(request,'login.html')

def logout_page(request):
    logout(request)
    return render(request,'login.html')

def getHashup(request):
    if(request.method=='POST'):
        username = request.user
        user = models.UserData.objects.get(user_name=username)
        key=user.key
        ring=user.ring
        special_ch=user.specialch
        plug=user.plug
        ref=Reflector(user.Reflactorr)
        rot1=Rotor(wiring=user.Router1,notchs=user.notch1)
        rot2=Rotor(wiring=user.Router2,notchs=user.notch2)
        rot3=Rotor(wiring=user.Router3,notchs=user.notch3)
        passkey=request.POST.get('key')
        num=number(passkey)
        length=createLength(passkey)
        enigma=Enigma(ref=ref,r1=rot1,r2=rot2,r3=rot3,key=key,ring=ring,plugs=plug)
        mess=enigma.encipher(length)+str(num)+special_ch
        req_password=Zconvert(mess)
        return render(request,'passDisplay.html',{'value':req_password})
    else:
        return render(request,'home.html')

def showpass(request):
    if request.method=='POST':
        url=request.POST.get('key')
        password=request.POST.get('getKey')
        user_instance = request.user
        person = models.savesPass(user_name=user_instance,URL=url,PassWord=password)
        person.save()
        return redirect('homepage')
    else:
        render(request,'passDisplay.html')

def password(request):
    user=models.savesPass.objects.filter(user_name=request.user)
    return render(request,'password.html',{'saved_passwords':user})