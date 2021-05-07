# -*- coding: utf-8 -*-

import hashlib
import binascii

def encrypt_cbc(m, iv , e, n): #Cypher Block Chaining


    #Division par blocs
    block_list = [char for char in m]

    #Conversion char en int
    for i in range(len(block_list)):
        block_list[i] = home_string_to_int(block_list[i])

    initialization_vector = iv

    #Initial encryption
    print(block_list)
    block_list[0] = initialization_vector ^ block_list[0]

    #encryption first block

    block_list[0] = home_mod_expnoent(block_list[0], e, n)


    for i in range(1, len(block_list)):
        print(i)
        print(block_list)
        block_list[i] = block_list[i-1] ^ block_list[i]
        block_list[i] = home_mod_expnoent(block_list[i], e, n)

    return block_list


def decrypt_cbc(block_list, iv, d, p, q):

    message_list = [None] * len(block_list)

    #message_list[0] = home_mod_expnoent(block_list[0], d, n)
    c = block_list[0]
    message_list[0] = mod_exp_crt(p, q, d, c)
    message_list[0] = message_list[0] ^ iv

    for i in range(1, len(block_list)):
        #message_list[i] = home_mod_expnoent(block_list[i], d, n)  #TODO: Implement CRT for message decryption
        c = block_list[i]
        message_list[i] = mod_exp_crt(p, q, d, c)
        message_list[i] = message_list[i] ^ block_list[i-1]

    #Conversion int en cha
    for i in range(len(block_list)):
        message_list[i] = home_int_to_string(message_list[i])
    
    return message_list

def mod_exp_crt(p, q, d, c):  #Modular exponentiation using CRT Algorithm (decrypting encrypyed message)

    if (q > p): p,q = q,p #q < p
    n = p*q
    q_inv = home_ext_euclide(p, q) #Inverse modulaire de q mod p
    dq = d % (q-1)
    dp = d % (p-1)

    mq = home_mod_expnoent(c, dq, q)
    mp = home_mod_expnoent(c, dp, p)

    h = ( (mp - mq) * q_inv ) % p
    m = (mq + h * q) % n

    return m

def home_mod_expnoent(x,y,n): #Exponentiation modulaire

    result = 1

    while y > 0:
        if y % 2 == 1:
            result = (result * x) % n
        x = (x * x) % n
        y = y // 2
    return result
            


def home_ext_euclide(y,b): #algorithme d'euclide étendu pour la recherche de l'exposant secret
    (r, nouvr, t, nouvt) = (y, b, 0, 1)

    while (nouvr > 1) :
        q = (r // nouvr)
        (r, nouvr, t, nouvt) = (nouvr, r % nouvr, nouvt, t-(q*nouvt))

    return nouvt % y


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



"""
def mot10char(): #entrer le secret
    secret=input("donner un secret de 10 caractères au maximum : ")
    while (len(secret)>50):
        secret=input("c'est beaucoup trop long, 10 caractères S.V.P : ")
    return(secret)


#TODO: Augmenter taille message
def mot50char(): #entrer le secret
    secret=input("donner un secret de 50 caractères au maximum : ")
    while (len(secret)>51):
        secret=input("c'est beaucoup trop long, 50 caractères S.V.P : ")
    return(secret)
"""
    

#Alice's keys

x1a=46729851468429981450596683934659799417296757155707833262801920174014214271791880250080149828203777515317 #p1 for sha256 (104 digits keys)
x2a=78576609692768067820821754278289758196321966686126130368838717805087052908022138028011573028777628837617 #q1 for sha256
na=x1a*x2a  #n
phia=((x1a-1)*(x2a-1))//home_pgcd(x1a-1,x2a-1)
ea=17 #Public key
da=home_ext_euclide(phia,ea) #Private key

#Bob's key

x1b=44974862217905051299604905779732073696318755181134355304715504703900165445769065766434794585211944116773 #p2 for sha256
x2b=27036107090286352347612559531240494672462139123470458244545933143045120802035142478857262597331090531877 #q2 for sha256

nb=x1b*x2b # n
phib=((x1b-1)*(x2b-1))//home_pgcd(x1b-1,x2b-1)
eb=23 #Public key
db=home_ext_euclide(phib,eb) #Private key



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
#secret=mot10char() #TODO: Augmenter taille message
#secret=mot50char()
secret=input("donner un secret de 10 caractères au maximum : ")
print("*******************************************************************")
print("voici la version en nombre décimal de ",secret," : ")
num_sec=home_string_to_int(secret)
print(num_sec)
print("voici le message chiffré avec la publique d'Alice : ")
chif=home_mod_expnoent(num_sec, ea, na)
print(chif)
print("*******************************************************************")
print("On utilise la fonction de hashage MD5 pour obtenir le hash du message",secret)
#Bhachis0=hashlib.md5(secret.encode(encoding='UTF-8',errors='strict')).digest() #MD5 du message #TODO: Implement sha256
Bhachis0=hashlib.sha256(secret.encode(encoding='UTF-8',errors='strict')).digest() #256 du message

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
#dechif=home_int_to_string(home_mod_expnoent(chif, da, na))
dechif = home_int_to_string( mod_exp_crt(x1a, x2a, da, chif))
print(dechif)
print("*******************************************************************")
print("Alice déchiffre la signature de Bob \n",signe,"\n ce qui donne  en décimal")
designe=home_mod_expnoent(signe, eb, nb)
print(designe)
print("Alice vérifie si elle obtient la même chose avec le hash de ",dechif)
#Ahachis0=hashlib.md5(dechif.encode(encoding='UTF-8',errors='strict')).digest() #TODO: Implement sha256
Ahachis0=hashlib.sha256(dechif.encode(encoding='UTF-8',errors='strict')).digest()


Ahachis1=binascii.b2a_uu(Ahachis0)
Ahachis2=Ahachis1.decode()
Ahachis3=home_string_to_int(Ahachis2)
print(Ahachis3)
print("La différence =", Ahachis3 - designe)
if (Ahachis3 - designe == 0):
    print("Alice : Bob m'a envoyé : ",dechif)
else:
    print("oups")

print("CBC : \n")
iv = 2500000293823823820 #TODO : Generate other IV

def convert(s):
  
    # initialization of string to ""
    str1 = ""
  
    # using join function join the list s by 
    # separating words by str1
    return(str1.join(s))

lala = encrypt_cbc(secret, iv, ea, na)
print(lala)
print("\n")
lolo = decrypt_cbc(lala, iv, da, x1a, x2a)

print (convert(lolo))
