from Cryptodome.Cipher import AES


def encrypt(key, data):
    """
    Encrypts data using the key

      Args
      key  : 16bit size string/integer
      data :  Byte data encoded

      """
    data = data.encode()
    cipher = AES.new(key, AES.MODE_EAX)
    encryptdata, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    return encryptdata, tag, nonce


def decrypt(key, data, tag, nonce):
    """
    Decrypts data

        Args
        key : AES EAX type Key
        data : encrypted data with the key
        tag : the output tag of the encryption
        nonce : AES EAX nonce output

    """
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decryptdata = cipher.decrypt_and_verify(data, tag)
    return decryptdata
