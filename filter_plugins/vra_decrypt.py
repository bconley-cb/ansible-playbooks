#!/usr/bin/python

def filter_vra_decrypt(v):

    from Crypto.Cipher import AES
    import base64, array

    key = array.array('B', [212,9,131,143,242,195,15,31,223,5,90,157,109,130,202,62]).tostring()
    iv = array.array('B', [76,65,231,33,111,205,5,19,23,80,99,6,235,28,10,53]).tostring()

    if not v or len(v) < 4 or v[-1] != "=":
        return v
    
    numtotrim = len(v) % 4
    v = v[0:len(v)-numtotrim]

    cipher = AES.new(key, AES.MODE_CBC, iv )

    decode = base64.b64decode(v)
    decrypted = cipher.decrypt(decode)
    unpadded = decrypted[:-ord(decrypted[len(decrypted)-1:])]
    return unpadded.decode('utf-8')
    
class FilterModule(object):
    filter_map = {
        'vra_decrypt': filter_vra_decrypt,
    }

    def filters(self):
        return self.filter_map
