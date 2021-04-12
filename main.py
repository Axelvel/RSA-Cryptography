# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Mr ABBAS-TURKI
"""



import hashlib
import binascii

def modinv(a: int, b: int) -> int:

    """return x such that (x * a) % b == 1"""
    g, x, _ = egcd(a, b)
    if g != 1:
        raise Exception('gcd(a, b) != 1')
    return x % b

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = egcd(b % a, a)
        return gcd, y - (b // a) * x, x



def home_mod_expnoent(x,y,n): #exponentiation modulaire

    result = 1

    while y > 0:
        if y % 2 == 1:
            result = (result * x) % n
        x = (x * x) % n
        y = y // 2
    return result
            


def home_ext_euclide(y,b): #algorithme d'euclide étendu pour la recherche de l'exposant secret

    r = b
    new_r = y

    #r = y
    #new_r = b

    # Coefficient de Bezout v
    v = 0
    new_v = 1

    while new_r != 0:
        print("r = ", r)
        print("new_r = ", new_r)
        q = r // new_r
        print ("q = ", q)
        #reste = r - new_r * q
        #r = new_r * q + reste

        var_a = new_r
        new_r = r - new_r * q
        r = var_a
        
        var_b = new_v
        new_v = v - new_v * q
        v = var_b

    if r > 1:
        print ("b n'est pas inversible mod y")
    if v < 0:
        v = v + b
    print("v = ", v)
    return v


def home_pgcd(a,b): #recherche du pgcd
    if(b==0): 
        return a 
    else: 
        return home_pgcd(b,a%b)

def home_string_to_int(x): # pour transformer un string en int
    z=0
    for i in reversed(range(len(x))):
        z=int(ord(x[i]))*pow(2,(8*i))+z
    return(z)


def home_int_to_string(x): # pour transformer un int en string
    txt=''
    res1=x
    while res1>0:
        res=res1%(pow(2,8))
        res1=(res1-res)//(pow(2,8))
        txt=txt+chr(res)
    return txt




def mot10char(): #entrer le secret
    secret=input("donner un secret de 10 caractères au maximum : ")
    while (len(secret)>11):
        secret=input("c'est beaucoup trop long, 10 caractères S.V.P : ")
    return(secret)
    

#voici les éléments de la clé d'Alice
x1a=2010942103422233250095259520183 #p
x2a=3503815992030544427564583819137 #q
na=x1a*x2a  #n
phia=((x1a-1)*(x2a-1))//home_pgcd(x1a-1,x2a-1)
ea=17 #exposant public
da=home_ext_euclide(phia,ea) #exposant privé
#voici les éléments de la clé de bob
x1b=9434659759111223227678316435911 #p
x2b=8842546075387759637728590482297 #q
nb=x1b*x2b # n
phib=((x1b-1)*(x2b-1))//home_pgcd(x1b-1,x2b-1)
eb=23 # exposants public
db=home_ext_euclide(phib,eb) #exposant privé



print("test : ")
print("ftc = ", home_mod_expnoent(25,15,17))
print("pow = ", pow(25,15,17))

print("Modular inverse : ", home_ext_euclide(23, 26))


print(modinv(26,23))

#print (egcd(23,26))





print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter")
print("n =",nb)
print("exposant :",eb)
print("voici votre précieux secret")
print("d =",db)
print("*******************************************************************")
print("Voici aussi la clé publique d'Alice que tout le monde peut conslter")
print("n =",na)
print("exposent :",ea)
print("*******************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*******************************************************************")
x=input("appuyer sur entrer")
secret=mot10char()
print("*******************************************************************")
print("voici la version en nombre décimal de ",secret," : ")
num_sec=home_string_to_int(secret)
print(num_sec)
print("voici le message chiffré avec la publique d'Alice : ")
chif=home_mod_expnoent(num_sec, ea, na)
print(chif)
print("*******************************************************************")
print("On utilise la fonction de hashage MD5 pour obtenir le hash du message",secret)
Bhachis0=hashlib.md5(secret.encode(encoding='UTF-8',errors='strict')).digest() #MD5 du message
print("voici le hash en nombre décimal ")
Bhachis1=binascii.b2a_uu(Bhachis0)
Bhachis2=Bhachis1.decode() #en string
Bhachis3=home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la clé privée de Bob du hachis")
signe=home_mod_expnoent(Bhachis3, db, nb)
print(signe)
print("*******************************************************************")
print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice \n",chif,"\n \t 2-et le hash signé \n",signe)
print("*******************************************************************")
x=input("appuyer sur entrer")
print("*******************************************************************")
print("Alice déchiffre le message chiffré \n",chif,"\nce qui donne ")
dechif=home_int_to_string(home_mod_expnoent(chif, da, na))
print(dechif)
print("*******************************************************************")
print("Alice déchiffre la signature de Bob \n",signe,"\n ce qui donne  en décimal")
designe=home_mod_expnoent(signe, eb, nb)
print(designe)
print("Alice vérifie si elle obtient la même chose avec le hash de ",dechif)
Ahachis0=hashlib.md5(dechif.encode(encoding='UTF-8',errors='strict')).digest()
Ahachis1=binascii.b2a_uu(Ahachis0)
Ahachis2=Ahachis1.decode()
Ahachis3=home_string_to_int(Ahachis2)
print(Ahachis3)
print("La différence =",Ahachis3-designe)
if (Ahachis3-designe==0):
    print("Alice : Bob m'a envoyé : ",dechif)
else:
    print("oups")
