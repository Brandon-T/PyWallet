MIT License

Copyright (c) 2017, XIO. https://github.com/Brandon-T/PyWallet

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.



import zipfile
import hashlib
import os.path
import json
import glob
import tempfile
import shutil
from distutils.dir_util import copy_tree
from CertSign import BIO, SMIME

class PKPass(object):
    def __init__(self, pass_directory_path):
        self.pass_directory_path = pass_directory_path
        self.__copyPass()
    
    def __del__(self):
        if self.temporary_directory is not None:
            shutil.rmtree(self.temporary_directory)

    def __copyPass(self):
        self.temporary_directory = tempfile.mkdtemp()
        self.temporary_path = self.temporary_directory + "/" + self.pass_directory_path.split("/")[-1]
        copy_tree(self.pass_directory_path, self.temporary_path)
        
        for file in glob.glob(self.temporary_path + "**/.DS_Store"):
            os.remove(file)

    def __createManifest(self):
        self.manifest = {}
            
        for filePath in glob.glob(self.temporary_path + "/**", recursive=True):
            if os.path.isdir(filePath) == False:
                file = open(filePath, "rb")
                data = file.read()
                file.close()
                
                key = os.path.relpath(filePath, self.temporary_path)
                self.manifest[key] = hashlib.sha1(data).hexdigest()
        
        manifest_string = json.dumps(self.manifest, cls=None, sort_keys=True, indent=4, ensure_ascii=False, separators=(',', ':'))
        file = open(self.temporary_path + "/manifest.json", "w")
        file.write(manifest_string)
        file.close()

    def readJSON(self):
        file = open(self.temporary_path + "/pass.json", "r")
        data = file.read()
        file.close()
        return data

    def writeJSON(self, payload):
        file = open(self.temporary_path + "/pass.json", "w")
        file.write(payload)
        file.close()

    def sign(self, key, cert, password=None):
        self.__createManifest()
            
        bio = BIO.fromFile(self.temporary_path + "/manifest.json")
        smime = SMIME(key, cert, password)
        pkcs7 = smime.sign(bio)
        
        bio = BIO.toFile(self.temporary_path + "/signature")
        pkcs7.toDER(bio)
    
    def compress(self, output_path):
        zip = zipfile.ZipFile(output_path, "w", zipfile.ZIP_STORED)
        for filePath in glob.glob(self.temporary_path + "/**", recursive=True):
            key = os.path.relpath(filePath, self.temporary_path)
            zip.write(filePath, key, zipfile.ZIP_DEFLATED)
        zip.close()
