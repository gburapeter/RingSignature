from ecpy.curves import Curve, Point
from ecpy.keys import ECPrivateKey
from ecpy.eddsa import EDDSA
import secrets, hashlib, binascii
import math
import itertools as it
import random
from pprint import pprint


### Az Ed-25519 curvet használom a program során ( Moneroban is )
### A görbének az egyenletét, jellemzőit kiprinteltem
### A G -generátorpont a későbbiekben is felhasználódik

curve = Curve.get_curve('Ed25519')
G     = curve.generator
pprint(f"Name: {curve.name}, Equation: -x^2 + y^2 = 1 -121665/121666 * x^2*y^2 (mod p) Type: {curve.type}")
pprint(f"Size: {curve.size}, a={curve.a}, d={curve.d}")
pprint(f"G={curve.generator}, field={curve.field}, order={curve.order}")
print()


### Hashelésre a következő hash függvényt választottam:
### Bemenetként egy stringet és egy elliptikus görbe Pontot kap meg
### Ezekből készit egy stringet amelyet hashel -> int
def H3(message, P1):
    
    str = "%s,%d,%d" % (message, P1.x, P1.y)
   
    #return int( hashlib.sha1( "H1_salt%s"%(str) ).hexdigest(), 16 )
    return int(hashlib.sha256(str.encode()).hexdigest(), 16)

### A ring_sign metódusba történik meg a signature elkészítése
### Inputként megkapjuk a görbét, az üzenetet, a ringben levő public-keyeket,
### a private_keyek egy arrayét- de ebből csak a signerét fogjuk használni
### key_index - ki a signer
###

def ring_sign(curve, message, public_keys, private_key, key_index):
    
    ### key_count - hány személy van a ringben
    ### előkészitjük az adott tömböket
    key_count = len(public_keys)
    e = [0] * key_count
    ss = [0] * key_count
    z_s = [0] * key_count
    
    ##Első lépés
    ### Alfát random választjuk meg, max a görbe rendjéig
    ### Kiszámoljuk Q-t (ami egy public keyként müködik), amely alfa*G (curve.mul_point - multiplication(scalar, Point))
    ### Meghatározzuk a pi_plus_1 indexet majd erre külön kiszámoljuk az e értékét
    alfa = random.randint(0,curve.order)
    Q = curve.mul_point(alfa, G)
    pi_plus_1 = (key_index+1) % key_count
    e[pi_plus_1] = H3(message, Q)

   
   #Második lépés
   ### Végigmegyünk a tömbön, úgy, hogy i != key_index, tehát a ring többi tagjára számolunk
    for i in it.chain(range(key_index+1, key_count), range(key_index)):
        if i!=key_index:
         # print(i)
         ###Meghatározunk egy random értéket
          ss[i] = random.randint( 0,curve.order )
         
         # print(ss[i])
         ### És az indexet
          next_i = (i+1) % key_count
          
         ### Két új EC pontot hozunk létre, ss_i és G illetve e_i és as publikus kulcsok(pontok) szorzatából
         # print(curve.is_on_curve(curve.mul_point(e[i],publicKeys[i].W)))
          z_s[i] = curve.add_point(curve.mul_point(ss[i],G), curve.mul_point(e[i],public_keys[i].W))
          e[next_i] = H3(message, z_s[i])


    ### Maga a signer részét, külön számoljuk ki. Itt kerül be a privát kulcsa
    #print(e)
    #ss[key_indexx] = (privateKeys[key_indexx].d  - signer.private_key * cs[signer_index] ) % curve.order
    ss[key_index] = ( alfa - private_key[key_index].d * e[key_index] ) % curve.order
    
    print("Signature részben kiszámolódik:")
    print("'e' tömb")
    pprint(e)
    print()
    print("s-k tömbje")
    pprint(ss)
    print()

    ###Visszaadjuk a publikus kulcsokat tartalmazó tömböket, az üzenetet, az első elemet az e-ből, és a random s-ket + a signer s-ét
    return (public_keys, message, e[0], ss)


### A signature ellenőrzése: meghatározza, hogy az 's' értékek mindenképpen az 'e' értékek után lettek kiszámolva,
### tehát közrejátszik egy private key felhasználása
### Megkapja a curvet, a public keyeket, az üzenetet, és az előzőleg kiszámolt e_0-t és s-k tömbjét

def verify(curve,public_keys, message, e_0, ss): 


    ### Tömböket előkészítem
    n = len(public_keys )
    e = [e_0] + [0] * ( n - 1 )
    z_s = [0] * n

    ###Végig iterálok a tömbön, és a signaturehez hasonlóan kiszámolom a z_s_i értékeket, amikkel az e-ket határozom meg
    for i in range( n ):
        z_s[i] = curve.add_point(curve.mul_point(ss[i],G),curve.mul_point( e[i],public_keys[i].W))
        if i < n - 1:
            e[i+1] = H3(message, z_s[i])
            #print(e)

    print("Verify részben:")
    print("e-k")
    pprint(e)
    print()
    print("to_check érték")
    to_check = H3(message, z_s[n-1])
    pprint(to_check)
    print()
    
    
    if (e[0]== to_check):
      pprint ("The signature is valid")
    else:
      pprint ("Invalid signature")



  ### Létrehozok 4 privát-public keypárt és a tömbökbe teszem
publicKeys=[]
privateKeys=[]
signer = EDDSA(hashlib.sha512)

#privKey = ECPrivateKey(secrets.randbits(32*8), curve)
#privKey2 = ECPrivateKey(secrets.randbits(32*8), curve)
#pubKey = signer.get_public_key(privKey, hashlib.sha512)

for x in range(4):
  privKey = ECPrivateKey(secrets.randbits(32*8), curve)
  pubKey = signer.get_public_key(privKey, hashlib.sha512)
  publicKeys.append(privKey.get_public_key())
  privateKeys.append(privKey)
  
  print("Priv - pubkey párok:")
  print(privKey)
  print(pubKey)
  print()


  ####TESZTELÉS#####
###Kiválasztom a 2-es indexen levő embert a signernek(de lehetne véletlenszerü is)
#key_index = random.randint(0,3)

key_index=2
message = "This is a ring signature"
verify(curve, *ring_sign(curve, message, publicKeys, privateKeys, key_index))