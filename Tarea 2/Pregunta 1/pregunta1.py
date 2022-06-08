from Crypto.Cipher import AES
from typing import Callable
from sys import byteorder

# Obtenido de https://nitratine.net/blog/post/xor-python-byte-strings/
def byte_xor(ba1: bytearray, ba2: bytearray) -> bytearray:
    return bytearray([a ^ b for a, b in zip(ba1, ba2)])

def davies_meyer(encrypt: Callable[[bytearray, bytearray],bytearray], l_key: int, l_message: int) -> Callable[[bytearray], bytearray]:
    """
    Arguments :
    encrypt : an encryption function
    l_key : length in bytes of the keys for encrypt
    l_message : length in bytes of the messages for encrypt

    Returns :
    A compression function from messages of length l_key + l_message to
    messages of length l_message , defined by using the Davies - Meyer
    construction
    """
    def compression(message: bytearray) -> bytearray:
        u = message[:l_key]
        v = message[l_key: l_message + l_key]
        return byte_xor(encrypt(u, v), v)

    return compression

def pad(message: bytearray, l_block: int) -> bytearray:
    """
    Arguments :
    message : message to be padded
    l_block : length in bytes of the block

    Returns :
    extension of message that includes the length of message
    ( in bytes ) in its last block
    """
    padded = bytearray(message[:])
    l_m = len(padded)
    # Bloque final con el largo del mensaje
    last_block = l_m.to_bytes(l_block, byteorder='big')
    if (len(message) % l_block == 0):
        padded.extend(last_block)
        return padded
    # Se obtiene el bloque incompleto a rellenar y se rellena con 100000...
    l_block_to_fill = l_m % l_block
    block_to_fill = padded[-l_block_to_fill:]
    l_to_fill = l_block - l_block_to_fill
    padded.extend(bytearray(b'\x01') + bytearray(l_to_fill - 1))
    # Se anade el ultimo bloque
    padded.extend(last_block)
    return padded

def merkle_damgard ( IV : bytearray , comp : Callable[[bytearray], bytearray] ,l_block : int ) -> Callable[[bytearray], bytearray]:
    """
    Arguments :
    IV : initialization vector for a hash function
    comp : compression function to be used in the Merkle - Damgard construction
    l_block : length in bytes of the blocks to be used in the Merkle - Damgard construction

    Returns :
    A hash function for messages of arbitrary length , defined by using the Merkle - Damgard construction
    """
    def hash(message: bytearray):
        msg = pad(message, l_block)
        h_i = IV
        for i in range(len(msg)//l_block):
            block = msg[l_block * i: l_block * i + l_block]
            h_i = comp(block + h_i)
        return h_i

    return hash

def encrypt(key: bytearray, msg: bytearray) -> bytearray:
    alg = AES.new(key, AES.MODE_ECB)
    return alg.encrypt(msg)

def AES_128(key: bytearray, message: bytearray) -> bytearray:
    a = AES.new(key, AES.MODE_ECB)
    return bytearray(a.encrypt(message))

if __name__ == "__main__":
    compresion = davies_meyer(AES_128, 16, 16)
    hash = merkle_damgard(bytearray(b'1234567890123456'), compresion, 16)

    s1 = bytearray(b'Este es un mensaje de prueba para la tarea 2')
    s2 = bytearray(b'Este es un mensaje de Prueba para la tarea 2')
    s3 = bytearray(b'Un mensaje corto')
    s4 = bytearray(b'')

    h1 = hash(s1)
    h2 = hash(s2)
    h3 = hash(s3)
    h4 = hash(s4)

    print(h1)
    print(h2)
    print(h3)
    print(h4)