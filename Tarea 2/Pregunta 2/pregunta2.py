################################################## Funciones necesarias para la implementación de las clases ################################################
import math
import random
import os
import time
from base64 import b64encode, b64decode

def exp(a: int, b: int) -> int:
    if b == 0:
        return 1
    else:
        res = 1
        pot = a
        while b > 0:
            if b % 2 == 1:
                res = pot * res
            b = b // 2
            pot = pot * pot
        return res

def exp_mod(a: int, b: int, n: int) -> int:
    if b == 0:
        return 1
    elif b > 0:
        res = 1
        pot = a
        while b > 0:
            if b % 2 == 1:
                res = (pot * res) % n
            b = b // 2
            pot = (pot * pot) % n
        return res
    else:
        return exp_mod(inverso(a,n),-b,n)

def mcd(a: int, b: int) -> int:
    while b > 0:
        temp = b
        b = a % b
        a = temp
    return a

def alg_ext_euclides(a: int, b: int) -> tuple[int, int, int]:
    r_0 = a
    s_0 = 1
    t_0 = 0
    r_1 = b
    s_1 = 0
    t_1 = 1
    while r_1 > 0:
        r_2 = r_0 % r_1
        s_2 = s_0 - (r_0 // r_1) * s_1
        t_2 = t_0 - (r_0 // r_1) * t_1
        r_0 = r_1
        s_0 = s_1
        t_0 = t_1
        r_1 = r_2
        s_1 = s_2
        t_1 = t_2
    return r_0, s_0, t_0

def inverso(a: int, n: int) -> int:
    (r, s, t) = alg_ext_euclides(a, n)
    return s % n

def es_potencia(n: int) -> bool:
    if n <= 3:
        return False
    else:
        k = 2
        lim = 4
        while lim <= n:
            if tiene_raiz_entera(n, k):
                return True
            k = k + 1
            lim = lim * 2
        return False

def tiene_raiz_entera(n: int, k: int) -> bool:
    if n <= 3:
        return False
    else:
        a = 1
        while exp(a,k) < n:
            a = 2*a
        return tiene_raiz_entera_intervalo(n, k, a//2, a)
    
def tiene_raiz_entera_intervalo(n: int, k: int, i: int, j: int) -> bool:
    while i <= j:
        if i==j:
            return n == exp(i,k)
        else:
            p = (i + j)//2 
            val = exp(p,k)
            if n == val:
                return True
            elif val < n:
                i = p+1
            else:
                j = p-1
    return False

def test_primalidad(n: int, k: int, check_potencia: bool) -> bool:
    if n == 1:
        return False
    elif n == 2:
        return True
    elif n%2 == 0:
        return False
    elif check_potencia and es_potencia(n):
        return False
    else:
        neg = 0
        checked = set()
        for i in range(1,k+1):
            a = random.randint(2,n-1)
            if a in checked:
                i-= 1
                continue
            else:
                checked.add(a)
            if mcd(a,n) > 1:
                return False
            else:
                b = exp_mod(a,(n-1)//2,n)
                if b == n - 1:
                    neg = neg + 1
                elif b != 1:
                    return False
        if neg > 0:
            return True
        else:
            return False

def prime_in_range(lower: int, upper: int, ti: float) -> int:
    checked = set()
    while True:
        a = random.randint(lower,upper-1)
        if a not in checked:
            checked.add(a)
            if test_primalidad(a, 20, False) and test_primalidad(a, 100, True):
                return a

def coprime_of(number: int, lower_bound: bytearray) -> (int, int, int):
    checked = set()

    n_bytes = math.ceil(lower_bound / 8)
    
    while True:
        candidate = random_bytes(n_bytes)
        candidate[0] = candidate[0] | 0x80
        candidate_number = int.from_bytes(candidate, "big")
        r, s, t = alg_ext_euclides(number, candidate_number)
        if r == 1: return (candidate_number, s, t)

def random_bytes(n_bytes: int) -> bytearray:
    return bytearray(os.urandom(n_bytes))

def random_prime_bytearray_in_range(lower_bound: int) -> bytearray:
    checked = set()
    # Se coloca como numero de bytes el techo de la division de lower_bound / 8 bits
    n_bytes = math.ceil(lower_bound / 8)
    while True:
        # Se escoge un numero al azar con el numero de bytes solicitado,
        # cuyo dígito más significativo es 1
        R = random_bytes(n_bytes)
        R[0] = R[0] | 0x80
        number = int.from_bytes(R, "big")
        if number not in checked:
            checked.add(number)
            if test_primalidad(number, 20, False) and test_primalidad(number, 100, True):
                return R

def PEM_format(k: int, N: int) -> bytearray:
    k_bytes = k.to_bytes(math.ceil(k.bit_length() / 8), byteorder="big")
    N_bytes = N.to_bytes(math.ceil(N.bit_length() / 8), byteorder="big")
    len_k = len(k_bytes).to_bytes(4, "big")
    len_N = len(N_bytes).to_bytes(4, "big")
    #len_N = bytearray([len(N_bytes)])
    return len_k + k_bytes + len_N + N_bytes

# def second_power(number: int):
#     counter = 0
#     while (number != 0):
#         number = number >> 1
#         counter += 1
#     return counter
######################################################################################################################################

class RSAReceiver :
    def __init__ ( self , bit_len : int ) -> None:
        """
        Arguments :
        bit_len : A lower bound for the number of bits of N ,
        the second argument of the public and secret key .
        """
        self._bit_len = bit_len
        self._private_key = None
        self._public_key = self.get_public_key()

    def get_public_key ( self ) -> bytearray :
        """
        Returns :
        public_key : Public key expressed as a Python ’ bytearray ’ using the
        PEM format . This means the public key is divided in :
        ( 1 ) The number of bytes of e ( 4 bytes )
        ( 2 ) the number e ( as many bytes as indicated in ( 1 ) )
        ( 3 ) The number of bytes of N ( 4 bytes )
        ( 4 ) the number N ( as many bytes as indicated in ( 3 ) )
        """
        prime_len = (self._bit_len // 2) + 1
        P_bytes = random_prime_bytearray_in_range(prime_len)
        P = int.from_bytes(P_bytes, "big")
        print(P)

        Q_bytes = random_prime_bytearray_in_range(prime_len)
        Q = int.from_bytes(Q_bytes, "big")
        print(Q)

        N = P * Q
        print("N:", N)
        phi = (P - 1) * (Q - 1)

        d, _, e = coprime_of(phi, self._bit_len)
        # Si e es negativo, para facilitar el trabajo con bytes, se usa el modulo N
        e = e % phi
        print("E:", e, "D:", d) 
        #print("E * D:", (e*d) % phi)
        self._private_key = PEM_format(d, N)

        return PEM_format(e, N)

    def decrypt ( self , ciphertext : bytearray ) -> str :
        """
        Arguments :
        ciphertext : The ciphertext to decrypt
        Returns :
        message : The original message
        """
        decrypted = bytearray()
        #print("Private key:", self._private_key)
        len_d_bytes = self._private_key[:4]
        len_d = int.from_bytes(len_d_bytes, "big")
        #print("Len d:", len_d, "Value:", len_d)
        d_bytes = self._private_key[4: 4 + len_d]
        d = int.from_bytes(d_bytes, "big")
        #print("decrypt D:", d_bytes, "Value:", d)
        len_N_bytes = self._private_key[4 + len_d: 4 + len_d + 4]
        len_N = int.from_bytes(len_N_bytes, "big")
        #print("Len N:", len_N_bytes, "Value:", len_N)
        N_bytes = self._private_key[8 + len_d: 8 + len_d + len_N]
        N = int.from_bytes(N_bytes, "big")
        #print("Decrytped N:", N_bytes, "Value:", N)
        chunk_size = len_N
        #print("Decrypted Chunk size:", chunk_size)
        #print("Ciphertext len:", len(ciphertext))
        for i in range(0, len(ciphertext), chunk_size):
            msg_int = int.from_bytes(ciphertext[i: i + chunk_size], "big")
            #print("I:", i, "Decrypted:", len(decrypted))
            #print("Msg chunk:", msg_int)
            
            #print("Bit length:",pow(msg_int, d, N).bit_length() / 8)
            #decrypted += pow(msg_int, d, N).to_bytes(len_N, "big")
            decrypted.extend(pow(msg_int, d, N).to_bytes(len_N, "big"))
        return decrypted.decode('utf-8').replace('\x00', '')
    
class RSASender :
    def __init__ ( self , public_key : bytearray ) -> None :
        """
        Arguments :
        public_key : The public key that will be used to encrypt messages
        """
        self._public_key = public_key

    def encrypt ( self , message : str ) -> bytearray :
        """
        Arguments :
        message : The plaintext message to encrypt
        Returns :
        ciphertext : The encrypted message
        """
        #print("Public key:", public_key)
        message_bytes = bytearray(message, "utf-8")
        encrypted = bytearray()
        len_e_bytes = self._public_key[:4]
        len_e = int.from_bytes(len_e_bytes, "big")
        #print("Len e:", len_e, "Value:", len_e)
        e_bytes = self._public_key[4: 4 + len_e]
        e = int.from_bytes(e_bytes, "big")
        #print("E:", e_bytes, "Value:", e)
        len_N_bytes = self._public_key[4 + len_e: 4 + len_e + 4]
        len_N = int.from_bytes(len_N_bytes, "big")
        #print("Len N:", len_N_bytes, "Value:", len_N)
        N_bytes = self._public_key[8 + len_e: 8 + len_e + len_N]
        N = int.from_bytes(N_bytes, "big")
        #print("Encrypt N:", N_bytes, "Value:", N)
        chunk_size = len_N - 1
        #print("Encrypted Chunk size:", chunk_size)
        for i in range(0, len(message_bytes), chunk_size):
            msg_int = int.from_bytes(message_bytes[i: i + chunk_size], "big")
            #print("Msg chunk:", msg_int)
            
            #print("Bit length:",pow(msg_int, e, N).bit_length() / 8)
            encrypted += pow(msg_int, e, N).to_bytes(len_N, "big")
        return encrypted

if __name__ == "__main__":
    
    public_key = b64decode('AAAAQQGHaihgiufnjzyLXufDjUCGuaHrsUL+hCF/pMFHPoh+ZVi/2bMFh6oelzElVklsJ9mglyQjJIKAb1JB9mvtaEkLAAAAQQHIuF+wIJw6uzq8uXpW/QmsNjtBJ8HCJJcu2h7sDX18nc2qWYDWTfMiXPmPRvhkkz4A0oXTAMDP9xsxUIjYQNsx')
    text = (
        'Being open source means anyone can independently review '
        'the code. If it was closed source, nobody could verify the '
        'security. I think it’s essential for a program of this '
        'nature to be open source.'
    )
    print("------------------------------------------------------------------")
    sender = RSASender(public_key)
    cipher = sender.encrypt(text)
    print(b64encode(cipher) == b'ALwPm7JXWbqGeIflV8PYgprs6mSgCH2Ydy0rgvFolzY0mczKItlPSHueL54uvDJXIz9pXoHZGAOPWVYYbcwRh3EBl8pi3MraUC2BBFUviMPFwNMwza/QMd5DNG9tH8doHlLRRt+15wLrsIE+m5T8fuM4HHixSNcEoOdN8T++q0PkzQDXL+UgbusiD3J+QPO59aqAB5HFcZ7P5U3fhFS8Qm1vLG8vlIulCby0jGLgjTtLUhFD/QhAof0y4F20gxedQDHwAOIrz6PEoBWnHmwLU0QNN0Rs542RvJ8BeEGhBDS5ZvD0/0Ix3ZqKT6HtP4ugfPD75/5LYGioJBwrg2DXbQucFj8=')
    print("------------------------------------------------------------------")
    reciever = RSAReceiver(1000)
    print(reciever._private_key, reciever._public_key)
    sender = RSASender(reciever._public_key)
    cipher = sender.encrypt(text)

    decrypted = reciever.decrypt(cipher)
    print("Encrypted:", len(cipher), cipher)
    print("Decrypted:", len(decrypted), "Type:", type(decrypted), decrypted)
    print(decrypted)
    print(text)
    print(decrypted==text)
