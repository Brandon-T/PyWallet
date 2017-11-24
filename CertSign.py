#MIT License
#
#Copyright (c) 2017, XIO. https://github.com/Brandon-T/PyWallet
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.



import base64
from sys import platform
from ctypes import *

openssl = cdll.LoadLibrary("libssl.so") if platform != "darwin" else cdll.LoadLibrary("/usr/local/opt/openssl/lib/libssl.dylib")

# Comment out this code only for purposes of testing.
# stdin = c_void_p.in_dll(openssl, "__stdinp")
# stdout = c_void_p.in_dll(openssl, "__stdoutp")

class BIO_MEM_BUF(Structure):
    _fields_ = [("length", c_size_t),
                ("data", c_char_p),
                ("max", c_size_t)]
        
    @staticmethod
    def fromBIO(bio):
        BIO_ctrl = openssl.BIO_ctrl
        BIO_ctrl.argtypes = [c_void_p, c_int, c_long, c_void_p]
        BIO_ctrl.restype = c_long
                    
        BIO_C_GET_BUF_MEM_PTR = 115
        buffer = POINTER(BIO_MEM_BUF)()
        BIO_ctrl(bio.getBIO(), BIO_C_GET_BUF_MEM_PTR, 0, byref(buffer))
        return buffer

class STStack(Structure):
    _fields_ = [("num", c_int),
                ("data", POINTER(c_char_p)),
                ("sorted", c_int),
                ("num_alloc", c_int),
                ("comp", CFUNCTYPE(c_int, c_void_p, c_void_p))]

class Stack_STX509(Structure):
    _fields_ = [("stack", STStack)]


class PKey(object):
    @staticmethod
    def new():
        EVP_PKEY_new = openssl.EVP_PKEY_new
        EVP_PKEY_new.argtypes = None
        EVP_PKEY_new.restype = c_void_p
        
        res = PKey()
        res.pkey = EVP_PKEY_new()
        return res
    
    @staticmethod
    def fromFile(path):
        PEM_read_bio_PrivateKey = openssl.PEM_read_bio_PrivateKey
        PEM_read_bio_PrivateKey.argtypes = [c_void_p, POINTER(c_void_p), c_void_p, c_void_p]
        PEM_read_bio_PrivateKey.restype = c_void_p
        
        bio = BIO.fromFile(path)
        res = PKey()
        res.pkey = PEM_read_bio_PrivateKey(bio.getBIO(), None, None, None)
        return res
    
    @staticmethod
    def fromBIO(bio):
        PEM_read_bio_PrivateKey = openssl.PEM_read_bio_PrivateKey
        PEM_read_bio_PrivateKey.argtypes = [c_void_p, POINTER(c_void_p), c_void_p, c_void_p]
        PEM_read_bio_PrivateKey.restype = c_void_p
        
        res = PKey()
        res.pkey = PEM_read_bio_PrivateKey(bio.getBIO(), None, None, None)
        return res
    
    def __del__(self):
        EVP_PKEY_free = openssl.EVP_PKEY_free
        EVP_PKEY_free.argtypes = [c_void_p]
        EVP_PKEY_free.restype = None
        EVP_PKEY_free(self.pkey)
        self.pkey = None
    
    def getKey(self):
        return self.pkey

class BIO(object):
    @staticmethod
    def fromFile(path):
        BIO_new_file = openssl.BIO_new_file
        BIO_new_file.argtypes = [c_char_p, c_char_p]
        BIO_new_file.restype = c_void_p
        
        res = BIO()
        res.bio = BIO_new_file(path.encode("utf-8"), "rb".encode("utf-8"))
        return res
    
    @staticmethod
    def toFile(path):
        BIO_new_file = openssl.BIO_new_file
        BIO_new_file.argtypes = [c_char_p, c_char_p]
        BIO_new_file.restype = c_void_p
        
        res = BIO()
        res.bio = BIO_new_file(path.encode("utf-8"), "wb".encode("utf-8"))
        return res
    
    @staticmethod
    def fromMemory(memory = None):
        if memory is not None:
            BIO_new_mem_buf = openssl.BIO_new_mem_buf
            BIO_new_mem_buf.argtypes = [c_void_p, c_int]
            BIO_new_mem_buf.restype = c_void_p
            
            res = BIO()
            res.bio = BIO_new_mem_buf(memory.encode("utf-8"), len(memory))
            return res
        
        BIO_s_mem = openssl.BIO_s_mem
        BIO_s_mem.argtypes = None
        BIO_s_mem.restype = c_void_p
        
        BIO_new = openssl.BIO_new
        BIO_new.argtypes = [c_void_p]
        BIO_new.restype = c_void_p
        
        res = BIO()
        res.bio = BIO_new(BIO_s_mem())
        return res

    @staticmethod
    def fromFilePointer(fp, flags):  #BIO_NOCLOSE = 0x00, BIO_CLOSE = 0x01
        BIO_new_fp = openssl.BIO_new_fp
        BIO_new_fp.argtypes = [c_void_p, c_int]
        BIO_new_fp.restype = c_void_p
        
        res = BIO()
        res.bio = BIO_new_fp(fp, flags)
        return res
    
    def puts(self, str_data):
        BIO_puts = openssl.BIO_puts
        BIO_puts.argtypes = [c_void_p, c_char_p]
        BIO_puts.restype = c_int
        return BIO_puts(self.bio, c_char_p(str_data))
    
    def toBytes(self):
        BIO_read = openssl.BIO_read
        BIO_read.argtypes = [c_void_p, c_void_p, c_int]
        BIO_read.restype = c_int
        
        totalBuffer = bytearray()
        
        while True:
            buffer = create_string_buffer(256)
            res = BIO_read(self.bio, cast(buffer, POINTER(c_ubyte)), sizeof(buffer))
            
            if res > 0:
                totalBuffer.extend(buffer.raw[:res])
            else:
                break

        return totalBuffer

    def toString(self):
        return self.toBytes().decode("utf-8")
    
    def __del__(self):
        BIO_free_all = openssl.BIO_free_all
        BIO_free_all.argtypes = [c_void_p]
        BIO_free_all.restype = None
        BIO_free_all(self.bio)
        self.bio = None
    
    def getBIO(self):
        return self.bio


class EVP_MD_CTX(object):
    def __init__(self):
        EVP_MD_CTX_create = openssl.EVP_MD_CTX_create
        EVP_MD_CTX_create.argtypes = None
        EVP_MD_CTX_create.restype = c_void_p
        self.ctx = EVP_MD_CTX_create()
    
    def __del__(self):
        EVP_MD_CTX_destroy = openssl.EVP_MD_CTX_destroy
        EVP_MD_CTX_destroy.argtypes = [c_void_p]
        EVP_MD_CTX_destroy.restype = None
        EVP_MD_CTX_destroy(self.ctx)
        self.ctx = None
    
    def getEVP(self):
        return self.ctx


class Digest(object):
    @staticmethod
    def fromName(digest_name):
        EVP_get_digestbyname = openssl.EVP_get_digestbyname
        EVP_get_digestbyname.argtypes = [c_char_p]
        EVP_get_digestbyname.restype = c_void_p
        
        res = Digest()
        res.md = EVP_get_digestbyname(digest_name.encode("utf-8"))
        return res
    
    
    def initEx(self, evp):
        EVP_DigestInit_ex = openssl.EVP_DigestInit_ex
        EVP_DigestInit_ex.argtypes = [c_void_p, c_void_p, c_void_p]
        EVP_DigestInit_ex.restype = c_int
        return EVP_DigestInit_ex(evp.getEVP(), self.md, None)
    
    def signInit(self, evp, pkey):
        EVP_DigestSignInit = openssl.EVP_DigestSignInit
        EVP_DigestSignInit.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]
        EVP_DigestSignInit.restype = c_int
        return EVP_DigestSignInit(evp.getEVP(), None, self.md, None, pkey.getKey())
    
    def signUpdate(self, evp, data, data_len):
        EVP_DigestSignUpdate = openssl.EVP_DigestUpdate
        EVP_DigestSignUpdate.argtypes = [c_void_p, c_void_p, c_size_t]
        EVP_DigestSignUpdate.restype = c_int
        return EVP_DigestSignUpdate(evp.getEVP(), data, data_len)
    
    def signFinal(self, evp, buffer, signature_len):
        EVP_DigestSignFinal = openssl.EVP_DigestSignFinal
        EVP_DigestSignFinal.argtypes = [c_void_p, POINTER(c_ubyte), POINTER(c_size_t)]
        EVP_DigestSignFinal.restype = c_int
        
        sig_len = c_size_t(signature_len)
        if buffer is None:
            EVP_DigestSignFinal(evp.getEVP(), buffer, byref(sig_len))
        else:
            EVP_DigestSignFinal(evp.getEVP(), cast(buffer, POINTER(c_ubyte)), byref(sig_len))
        return sig_len
    
    def sign(self, evp, pkey, data, data_len):
        self.initEx(evp)
        self.signInit(evp, pkey)
        self.signUpdate(evp, data, data_len)
        
        signature_len = self.signFinal(evp, None, 0)
        buffer = create_string_buffer(signature_len.value)
        self.signFinal(evp, buffer, signature_len)
        return base64.b64encode(buffer.raw).decode("utf-8")
    
    def getMD(self):
        return self.md


class PKCS7(object):
    @staticmethod
    def fromFile(path):
        d2i_PKCS7_bio = openssl.d2i_PKCS7_bio
        d2i_PKCS7_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_PKCS7_bio.restype = c_void_p
        
        res = PKCS7()
        bio = BIO.fromFile(path)
        res.pkcs7 = d2i_PKCS7_bio(bio.getBIO(), None)
        return res
    
    @staticmethod
    def fromMemory(data):
        d2i_PKCS7 = openssl.d2i_PKCS7
        d2i_PKCS7.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), c_long]
        d2i_PKCS7.restype = c_void_p
        
        res = PKCS7()
        buffer = cast(data, POINTER(c_ubyte))
        res.pkcs7 = d2i_PKCS7(None, byref(buffer), len(data))
        return res
    
    @staticmethod
    def fromBIO(bio):
        d2i_PKCS7_bio = openssl.d2i_PKCS7_bio
        d2i_PKCS7_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_PKCS7_bio.restype = c_void_p
        
        res = PKCS7()
        res.pkcs7 = d2i_PKCS7_bio(bio.getBIO(), None)
        return res
    
    def __del__(self):
        PKCS7_free = openssl.PKCS7_free
        PKCS7_free.argtypes = [c_void_p]
        PKCS7_free.restype = None
        PKCS7_free(self.pkcs7)
        self.pkcs7 = None
    
    def getPKCS7(self):
        return self.pkcs7
    
    def toDER(self, out_bio=None):
        i2d_PKCS7_bio = openssl.i2d_PKCS7_bio
        i2d_PKCS7_bio.argtypes = [c_void_p, c_void_p]
        i2d_PKCS7_bio.restype = c_int
        
        bio = out_bio if out_bio is not None else BIO.fromMemory()
        if i2d_PKCS7_bio(bio.getBIO(), self.pkcs7):
            return bio
        return None


class PKCS8(object):
    @staticmethod
    def fromFile(path):
        d2i_PKCS8_bio = openssl.d2i_PKCS8_bio
        d2i_PKCS8_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_PKCS8_bio.restype = c_void_p
        
        res = PKCS8()
        bio = BIO.fromFile(path)
        res.pkcs8 = d2i_PKCS8_bio(bio.getBIO(), None)
        return res
    
    @staticmethod
    def fromMemory(data):
        d2i_PKCS8 = openssl.d2i_PKCS8
        d2i_PKCS8.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), c_long]
        d2i_PKCS8.restype = c_void_p
        
        res = PKCS8()
        buffer = cast(data, POINTER(c_ubyte))
        res.pkcs8 = d2i_PKCS8(None, byref(buffer), len(data))
        return res
    
    @staticmethod
    def fromBIO(bio):
        d2i_PKCS8_bio = openssl.d2i_PKCS8_bio
        d2i_PKCS8_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_PKCS8_bio.restype = c_void_p
        
        res = PKCS8()
        res.pkcs8 = d2i_PKCS8_bio(bio.getBIO(), None)
        return res
    
    def __del__(self):
        PKCS8_free = openssl.PKCS8_free
        PKCS8_free.argtypes = [c_void_p]
        PKCS8_free.restype = None
        PKCS8_free(self.pkcs8)
        self.pkcs8 = None
    
    def getPKCS8(self):
        return self.pkcs8

class PKCS12(object):
    def __init__(self):
        self.password = ""
        self.pkey = None
        self.pkcs12 = None
        self.x509 = None
    
    @staticmethod
    def fromFile(path, password=None):
        d2i_PKCS12_bio = openssl.d2i_PKCS12_bio
        d2i_PKCS12_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_PKCS12_bio.restype = c_void_p
        
        res = PKCS12()
        bio = BIO.fromFile(path)
        res.password = password
        res.pkcs12 = d2i_PKCS12_bio(bio.getBIO(), None)
        return res
    
    @staticmethod
    def fromMemory(data, password=None):
        d2i_PKCS12 = openssl.d2i_PKCS12
        d2i_PKCS12.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), c_long]
        d2i_PKCS12.restype = c_void_p
        
        res = PKCS12()
        buffer = cast(data, POINTER(c_ubyte))
        res.password = password
        res.pkcs12 = d2i_PKCS12(None, byref(buffer), len(data))
        return res
    
    @staticmethod
    def fromBIO(bio, password=None):
        d2i_PKCS12_bio = openssl.d2i_PKCS12_bio
        d2i_PKCS12_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_PKCS12_bio.restype = c_void_p
        
        res = PKCS12()
        res.password = password
        res.pkcs12 = d2i_PKCS12_bio(bio.getBIO(), None)
        return res
    
    def verify(self):
        if self.password is None:
            self.password = ""
        
        PKCS12_verify_mac = openssl.PKCS12_verify_mac
        PKCS12_verify_mac.argtypes = [c_void_p, c_char_p, c_int]
        PKCS12_verify_mac.restype = c_int
        return PKCS12_verify_mac(self.pkcs12, self.password, len(self.password))
    
    def parse(self):
        if self.password is None:
            self.password = ""
        
        PKCS12_parse = openssl.PKCS12_parse
        PKCS12_parse.argtypes = [c_void_p, c_char_p, POINTER(c_void_p), POINTER(c_void_p), POINTER(Stack_STX509)]
        PKCS12_parse.restype = c_int
        
        pkey = c_void_p()
        x509 = c_void_p()
        res = PKCS12_parse(self.pkcs12, self.password.encode("utf-8"), byref(pkey), byref(x509), None)
        
        if pkey:
            self.pkey = PKey()
            self.pkey.pkey = pkey
        
            if x509:
                self.x509 = X509Certificate()
                self.x509.x509 = x509
            return res

    def __del__(self):
        PKCS12_free = openssl.PKCS12_free
        PKCS12_free.argtypes = [c_void_p]
        PKCS12_free.restype = None
        PKCS12_free(self.pkcs12)
        self.pkcs12 = None

    def getPKCS12(self):
        return self.pkcs12

    def getPrivateKey(self):
        return self.pkey
    
    def getCertificate(self):
        return self.x509


class X509Certificate(object):
    @staticmethod
    def fromPEM(path):
        PEM_read_bio_X509 = openssl.PEM_read_bio_X509
        PEM_read_bio_X509.argtypes = [c_void_p, POINTER(c_void_p), c_void_p, c_void_p]
        PEM_read_bio_X509.restype = c_void_p
        
        res = X509Certificate()
        bio = BIO.fromFile(path)
        res.x509 = PEM_read_bio_X509(bio.getBIO(), None, None, None)
        res.pkey = PKey.fromBIO(bio)
        return res
    
    @staticmethod
    def fromDER(path):
        d2i_X509_bio = openssl.d2i_X509_bio
        d2i_X509_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_X509_bio.restype = c_void_p
        
        res = X509Certificate()
        bio = BIO.fromFile(path)
        res.x509 = d2i_X509_bio(bio.getBIO(), None)
        res.pkey = PKey.fromBIO(bio)
        return res
    
    @staticmethod
    def fromMemory(data):
        d2i_X509 = openssl.d2i_X509
        d2i_X509.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), c_long]
        d2i_X509.restype = c_void_p
        
        bio = BIO.fromMemory(data)
        
        res = X509Certificate()
        buffer = cast(data, POINTER(c_ubyte))
        res.x509 = d2i_X509(None, byref(buffer), len(data))
        res.pkey = PKey.fromBIO(bio)
        return res
    
    @staticmethod
    def fromBIO(bio):
        d2i_X509_bio = openssl.d2i_X509_bio
        d2i_X509_bio.argtypes = [c_void_p, POINTER(c_void_p)]
        d2i_X509_bio.restype = c_void_p
        
        res = X509Certificate()
        res.x509 = d2i_X509_bio(bio.getBIO(), None)
        res.pkey = PKey.fromBIO(bio)
        return res
    
    def __del__(self):
        X509_free = openssl.X509_free
        X509_free.argtypes = [c_void_p]
        X509_free.restype = None
        X509_free(self.x509)
        self.x509 = None
    
    def writeToBIO(self, bio):
        X509_print = openssl.X509_print
        X509_print.argtypes = [c_void_p, c_void_p]
        X509_print.restype = None
        X509_print(bio.getBIO(), self.x509)
    
    def toString(self):
        bio = BIO.fromMemory()
        self.writeToBIO(bio)
        return bio.toString()
    
    def getX509(self):
        return self.x509
    
    def getPrivateKey(self):
        return self.pkey

class SMIME(object):
    def __init__(self, keyPath, certificatePath, password=None):
        self.pkcs12 = PKCS12.fromFile(keyPath, password)
        self.cert = X509Certificate.fromPEM(certificatePath)
        self.digest = Digest.fromName("sha1")
        self.pkcs12.parse()
    
    def sign(self, bio):
        #constants
        PKCS7_DETACHED = 0x40
        PKCS7_BINARY = 0x80
        PKCS7_STREAM = 0x1000
        flags = PKCS7_BINARY | PKCS7_DETACHED
        
        #signing functions
        PKCS7_sign = openssl.PKCS7_sign
        PKCS7_sign.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_int]
        PKCS7_sign.restype = c_void_p
        
        PKCS7_sign_add_signer = openssl.PKCS7_sign_add_signer
        PKCS7_sign_add_signer.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_int]
        PKCS7_sign_add_signer.restype = c_void_p
        
        PKCS7_final = openssl.PKCS7_final
        PKCS7_final.argtypes = [c_void_p, c_void_p, c_int]
        PKCS7_final.restype = c_int
        
        PKCS7_add_certificate = openssl.PKCS7_add_certificate
        PKCS7_add_certificate.argtypes = [c_void_p, c_void_p]
        PKCS7_add_certificate.restype = c_int
        
        #sign
        pkcs7 = PKCS7_sign(self.cert.getX509(), self.cert.getPrivateKey().getKey(), None, bio.getBIO(), flags | PKCS7_STREAM)
        PKCS7_sign_add_signer(pkcs7, self.pkcs12.getCertificate().getX509(), self.pkcs12.getPrivateKey().getKey(), self.digest.getMD(), flags)
        PKCS7_add_certificate(pkcs7, self.cert.getX509())
        PKCS7_final(pkcs7, bio.getBIO(), flags)
        
        res = PKCS7()
        res.pkcs7 = pkcs7
        return res


def initializeOpenSSL():
    openssl.SSL_library_init()
    openssl.OPENSSL_add_all_algorithms_noconf()
    openssl.SSL_load_error_strings()
    openssl.OpenSSL_add_all_ciphers()
    openssl.OpenSSL_add_all_digests()

def freeOpenSSL():
    openssl.ERR_free_strings()
    openssl.EVP_cleanup()
    openssl.CRYPTO_cleanup_all_ex_data()
