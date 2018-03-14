# -*- coding: utf-8 -*-
"""
Created on Thu Mar 08 20:17:09 2018

@author: Nightzsky
"""


languages = [{'name':'JavaScript'},{'name':'Python'},{'name':'Ruby'}]
users = {}
orgs = {}

from flask import Flask,jsonify,request,Response
#from __future__ import print_function
#import sys
#import demo
#import crypto_functions
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import json
import requests
import os
from functools import wraps
app = Flask(__name__)


@app.route("/")
def receiveInformation():
    return "bye"

@app.route("/lang")
def hello():    
    return jsonify({"languages":languages})

@app.route("/register_kyc", methods = ['POST'])
def register_kyc():
    #create a new dictionary
    user_info = {}  
    
    #retrieve data
    name = request.json["name"]
    postal_code = request.json["postal_code"]
    id_number = request.json["id_number"]
    dob = request.json["dob"]

    #add it to the user_info dictionary
    user_info["name"] = name
    user_info["postal_code"] = postal_code       
    user_info["id_number"] = id_number
    user_info["dob"] = dob
    
    #generate key
    AES_key = Random.new().read(32)
#    print type(AES_key)
    print("Generating AES key: %s"%AES_key)

    RSA_pvt_key = RSA.generate(2048)
    RSA_pub_key = RSA_pvt_key.publickey()
        
    #create Merkle tree hash from user information, and add it to the dictionary
    merkle_raw = user_info.copy().values() #make a copy of the information used to create the merkle tree 
    hashed_info = [hash256(item) for item in merkle_raw]
    merkles = merkle(hashed_info)
    print("Computed merkle root: %s"%merkles)
    print("Storing merkle root in user info")
    user_info["merkle"] = merkles
        
    #write key to the file then read the same file to obtain the key in plaintext
    f = open("publicKey.pem", "a+b")
    f.write(RSA_pub_key.exportKey('PEM'))
    f.seek(0)
    RSA_pub_key_str = f.read()
    print("Generating RSA public key: %s"%RSA_pub_key_str)
    f.close()
    #delete file after this to prevent key from being stored as a file
    os.remove("publicKey.pem")
    print("Storing RSA public key in user info")
    user_info["public_key"] = RSA_pub_key_str
        
    encrypted_user_info = {}
    print("Encrypting user info:%s"%str(user_info))
    for key in user_info:
        encrypted_user_info[key] = aes_encrypt(user_info[key], AES_key)
    print("Encrypted user info: %s"%str(encrypted_user_info))
    print("Storing encrypted user info in block")
        
    #    block = Block(encrypted_user_info)
    #    print("block id: %d"%block.id)
    block_id = hash256(user_info["id_number"])
#    headers = {"Content-Type":"application/json"}
    payload = {"$class": "org.acme.biznet.User","userId": block_id,"name": encrypted_user_info["name"],"userData": {"$class": "org.acme.biznet.UserData","name": encrypted_user_info["name"],"id": encrypted_user_info["id_number"],"postcode": encrypted_user_info["postal_code"],"birthdate": encrypted_user_info["dob"]},"access": True}
    r = requests.post("http://173.193.102.98:31090/api/User", json = payload)

    print(r.status_code)
    print(r.text)
    #store private key, AES key, and user's block id in the token
    #first get private key as plaintext
    f = open("privateKey.pem", "a+b")
    f.write(RSA_pvt_key.exportKey('PEM'))
    f.seek(0)
    RSA_pvt_key_str = f.read()
    print("Generating RSA private key: %s"%RSA_pvt_key_str)
    f.close()
    #delete file after this to prevent key from being stored as a file
    os.remove("privateKey.pem")
    #create the token object, and assign it to the user who is registering
    print("Storing RSA private key, AES key, block ID and information used to compute merkle root in token")
    #    token = demo.Token(RSA_pvt_key_str,AES_key,0,merkle_raw)
    print("Token sent to user")
    
    token = {}
    token["private key"] = RSA_pvt_key_str.decode("utf-8")
    token["AES key"] = AES_key.decode("cp437")
    token["block id"] = block_id
    token["merkle raw"] = merkles
        
    print(token)
        
        
        
    resp = Response(json.dumps(token))
    resp.status_code = 200
    print(resp)
        
        
    #post the data to the blockchain 
    #    blockchain_ip = "173.193.102.98"
    #    
    #    r = requests.post("http://%s:31090/api/revokeAccess"%blockchain_ip, json = encrypted_user_info)
    #
    #    print r
    #    print r.status_code
    #    print r.text
     
    print("received data")
        
    languages.append(user_info)
    return resp


 
#function which encrypts data using AES
def aes_encrypt(data,key):
	#process data to become suitable for encryption by converting to bytes if needed
	if type(data) != bytes:
		data = bytes(data, encoding = "utf8")
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB,iv)
	return str(list((iv+cipher.encrypt(data))))

#function which decrypts data using AES
def aes_decrypt(data,key):
	if type(data) != bytes:
		try:
			data = bytes(ast.literal_eval(data))
		except:
			print("Error: could not interpret data for decryption")
			return
	iv = data[:16]
	cipher = AES.new(key, AES.MODE_CFB, iv)
	decrypted = cipher.decrypt(data[16:]).decode()
	return decrypted

#function which encrypts data using RSA
def rsa_encrypt(data, public_key):
	if type(data) != bytes:
		data = bytes(data, encoding = "utf8")
	cipher = PKCS1_OAEP.new(public_key)
	#hybrid encryption is used here as PKCS1_OAEP can only encrypt a very small amount of data
	#to get around this, AES is used for the encryption of the data, and the AES key is encrypted using RSA
	session_key = Random.get_random_bytes(16)
	encrypted_data = aes_encrypt(data,session_key)
	encrypted_session_key = cipher.encrypt(session_key)
	return [encrypted_data, encrypted_session_key]

#function which decrypts data using RSA
def rsa_decrypt(data, private_key):
	cipher = PKCS1_OAEP.new(private_key)
	#first decrypt the session key using RSA
	session_key = cipher.decrypt(data[1])
	#then decrypt the data using AES and the session key
	return aes_decrypt(data[0], session_key)


#computes a SHA256 hash of the data
def hash256(data):
	data = bytes(data, encoding = "utf8")
	hash_object = SHA256.new(data=data)
	return hash_object.hexdigest()

#function that returns the root hash of the merkle tree from a list of data
#it assumes that everything in the data has already been hashed
def merkle(data):
	#base case, only one data point, return that one data point
	if len(data) == 1:
		return data[0]

	#another base case, compute hash of the concatenation of the 2 leaves
	if len(data) == 2:
		return hash256(data[0] + data[1])

	#if odd number, ignore last data point  
	if (len(data)%2 != 0):
		data = data[:-1]

	#recursively traverse the merkle tree from bottom to top to get the root hash
	temp = []
	for i in range(0,len(data),2):
		temp.append(merkle(data[i:i+2]))

	return merkle(temp)



#def check_auth(username, password):
#    return username == 'admin' and password == 'secret'
#
#def authenticate():
#    message = {'message':"Authenticate."}
#    
#    resp = jsonify(message)
#    resp.status_code = 401
#    resp.headers['WWW-Authenticate'] = 'Basic realm = "Example"'
#    
#    return resp
#
#def requires_auth(f):
#    @wraps(f)
#    def decorated(*args,**kwargs):
#        auth = request.authorization
#        if not auth:
#            return authenticate()
#        
#        elif not check_auth(auth.username, auth.password):
#            return authenticate()
#        return f(*args, **kwargs)
#    
#    return decorated
    

if __name__ == "__main__":
    app.run()