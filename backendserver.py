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
    token["private_key"] = RSA_pvt_key_str.decode("utf-8")
    token["AES_key"] = AES_key.decode("cp437")
    token["block_id"] = block_id
    token["merkle_raw"] = merkles
        
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

@app.route("/register_org", methods=['POST'])
def register_org():
    user_block_id = request.json["block_id"]
    
    if (user_block_id == "12345"):
        data = {'name': '[5, 230, 170, 125, 175, 195, 164, 225, 200, 194, 162, 168, 242, 239, 132, 208, 136, 91, 221]', 'postal_code': '[83, 12, 90, 215, 32, 76, 53, 56, 81, 173, 174, 211, 236, 225, 75, 22, 206, 232, 5, 211, 234, 87]', 'id_number': '[197, 185, 240, 180, 246, 35, 110, 56, 80, 169, 77, 29, 64, 62, 111, 233, 187, 203, 167, 75, 6, 242, 99, 63, 168, 209, 137]', 'dob': '[77, 134, 83, 71, 225, 156, 157, 125, 116, 14, 51, 3, 10, 74, 132, 85, 58, 126, 240, 75, 135, 182, 191, 106, 166, 197]', 'merkle': '[233, 139, 201, 123, 169, 203, 140, 194, 176, 162, 25, 180, 208, 145, 192, 39, 112, 191, 141, 60, 147, 110, 75, 185, 5, 30, 24, 243, 80, 214, 74, 158, 98, 133, 46, 93, 53, 44, 246, 15, 208, 6, 140, 15, 7, 47, 117, 128, 115, 150, 2, 147, 14, 33, 37, 70, 183, 92, 162, 40, 81, 32, 109, 107, 221, 95, 206, 13, 15, 93, 62, 160, 92, 114, 27, 21, 186, 228, 17, 117]', 'public_key': '[208, 0, 9, 19, 156, 253, 173, 125, 153, 148, 146, 96, 12, 213, 187, 211, 74, 85, 187, 22, 230, 63, 198, 124, 238, 157, 66, 156, 59, 88, 94, 175, 39, 20, 162, 36, 203, 237, 90, 92, 28, 80, 71, 27, 227, 16, 191, 138, 191, 9, 75, 11, 238, 209, 145, 30, 102, 160, 2, 55, 146, 79, 142, 102, 188, 176, 22, 207, 197, 200, 78, 51, 83, 173, 121, 124, 51, 46, 228, 221, 91, 16, 139, 84, 94, 71, 189, 22, 60, 194, 116, 75, 120, 165, 61, 232, 193, 30, 38, 49, 236, 221, 1, 167, 66, 190, 241, 35, 85, 195, 199, 141, 150, 169, 75, 251, 105, 166, 97, 153, 48, 184, 208, 19, 22, 125, 28, 143, 66, 167, 102, 72, 98, 187, 156, 48, 15, 203, 74, 186, 46, 146, 23, 213, 202, 192, 38, 57, 228, 47, 222, 195, 106, 140, 84, 197, 4, 192, 80, 159, 234, 186, 56, 15, 166, 59, 124, 80, 192, 211, 57, 47, 183, 23, 100, 179, 50, 103, 198, 31, 154, 110, 230, 106, 44, 129, 181, 83, 28, 9, 213, 203, 52, 101, 3, 85, 7, 194, 67, 0, 126, 85, 44, 195, 201, 109, 16, 169, 127, 98, 180, 151, 6, 173, 216, 149, 81, 75, 12, 88, 45, 51, 189, 67, 155, 94, 184, 232, 79, 233, 81, 163, 161, 85, 98, 6, 211, 27, 29, 1, 88, 84, 245, 214, 248, 127, 7, 95, 142, 243, 202, 227, 202, 135, 84, 255, 139, 52, 213, 108, 245, 237, 81, 44, 242, 56, 168, 87, 136, 24, 234, 72, 46, 186, 62, 226, 104, 54, 206, 51, 251, 139, 140, 239, 75, 172, 81, 99, 203, 100, 139, 52, 251, 135, 225, 193, 155, 115, 48, 36, 38, 89, 4, 184, 207, 29, 47, 141, 4, 211, 236, 198, 241, 139, 30, 156, 224, 151, 81, 94, 148, 18, 44, 70, 186, 83, 197, 118, 254, 103, 172, 142, 247, 151, 111, 120, 29, 235, 192, 123, 37, 109, 15, 188, 161, 233, 14, 136, 178, 123, 66, 182, 72, 56, 122, 62, 239, 106, 72, 84, 84, 62, 222, 241, 21, 244, 52, 32, 205, 9, 221, 235, 4, 117, 7, 171, 238, 170, 209, 242, 40, 161, 35, 118, 73, 139, 250, 7, 65, 140, 121, 195, 125, 241, 0, 28, 60, 142, 116, 81, 38, 14, 157, 222, 89, 71, 241, 124, 244, 38, 205, 224, 129, 247, 26, 42, 83, 16, 148, 198, 79, 190, 227, 99, 86, 112, 78, 113, 184, 184, 165, 18, 189, 167, 98, 37, 44, 132, 7, 169, 18, 201, 194, 197, 149, 171, 141, 112, 21, 179, 160, 71, 119, 148, 201, 236, 181, 202, 57, 138, 190, 213, 162, 243, 239, 229]'}
        resp = Response(json.dumps(data))
        resp.status_code = 200
        print(resp)
        
    else:
        data = {"messages":"invalid user"}
        resp = Response(json.dumps(data))
        resp.status_code = 200
        print(resp)
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