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
        encrypted_user_info[aes_encrypt(key, AES_key)] = aes_encrypt(user_info[key], AES_key)
    print("Encrypted user info: %s"%str(encrypted_user_info))
    print("Storing encrypted user info in block")
    
#    block = Block(encrypted_user_info)
#    print("block id: %d"%block.id)
    block_id = 0
    print ("block id : 0")
    
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
    
    Token = {}
    Token["private key"] = RSA_pvt_key
    Token["AES key"] = AES_key
    Token["block id"] = block_id
    Token["merkle raw"] = merkles
    
    print Token
    
    
    outputData = jsonify(Token)
    
    resp = Response(outputData, status = 200, mimetype = 'application/json')
#    print resp
    
    
#    self.setToken(token)
    
    #post the data to the blockchain 
#    blockchain_ip = "173.193.102.98"
#    
#    r = requests.post("http://%s:31090/api/revokeAccess"%blockchain_ip, json = encrypted_user_info)
#
#    print r
#    print r.status_code
#    print r.text
 
    print "received data"
#    users[id_number] = user
#    user.register_kyc()
#    for keys,values in users.items():
#      print(keys)

#    Userinfo = {"name":name,"postal_code":postal_code,"id_number":id_number,"dob":dob}
    
    languages.append(user_info)
    return "hi"
#    return jsonify(user_info)

#@app.route("/register_org", methods = ['POST'])
#def register_org():
#    request_received = request.json["request"]
#    if (request_received == "generate_keys"):
#        org_name = request.json["org_name"]
#        RSA_pvt_key = RSA.generate(2048)
#        RSA_pub_key = RSA_pvt_key.publickey()
#        
#        org_data = {}
#        org_data["name"] = org_name
#        org_data["private key"] = RSA_pvt_key
#        org_data["public key"] = RSA_pub_key
#        
#        return jsonify(org_data)
#    
#    else if (request_received == "encrypt_key_id"):
#        RSA_pub_key = request.json["public key"]
#        AES_key = request.json["AES key"]
#        block_id = request.json["block_id"]
#        
#        encrypted_AES_key = RSA_encrypt(AES_key, RSA_pub_key)
#        
#        encrypted_key_id = {}
#        encrypted_key_id["AES key"] = encrypted_AES_key
#        encrypted_key_id["Block id"] = block_id
#        
#        return jsonify(encrypted_key_id)
#    
#    else if (request_received == "access_user_block"):
#        RSA_pvt_key = request.json["private key"]
#        encrypted_AES_key = request.json["AES key"]
#        block_id = request.json["Block id"]
#        username = request.json["username"]
#        password = request.json["password"]
#        
#        decrypted_AES_key = RSA_decrypt(encrypted_AES_key, RSA_pvt_key)
#        block_list = {"111": {"name":"hi"}}
#        
#        if block not in block_list_id.keys():
#            message = {"message":"Block ID is invalid/does not exists!"}
#            return jsonify(message)
#        else:
#            encrypted_block = block_list_id[block_id]
#            decrypted_block = aes_decrypt(encrypted_block, decrypted_AES_key)
#            return jsonify(decrypted_block)
#        
#    else if (request_received == "reencrypt_block"):
#        new_AES_key = 
        
        

#@app.route("/login_org", methods = ['POST'])
#def loginorg():
#    org_name = request.json["org_name"]
#    if org_name not in orgs:
#        org = demo.Organization(org_name)
#        orgs[org_name] = org
#    else:
#        org = orgs[org_name]
#    demo.login_org(org)
#    
##function which allows a user to register with a organization, provided that he has already registered with KYC service
#def register_org(self,org):
#	#organization first generates a public-private key pair, and sends the public key to the user
#	org.generateKey()
#	#write key to the file then read the same file to obtain the key in plaintext
#	f = open("publicKey.pem", "a+b")
#	f.write(org.RSA_pub_key.exportKey('PEM'))
#	f.seek(0)
#	RSA_pub_key_str = f.read()
#	print("%s generating RSA public key: %s"%(org.name,RSA_pub_key_str))
#	f.close()
#
#	#delete file after this to prevent key from being stored as a file
#	os.remove("publicKey.pem")
#	print("%s sending RSA public key to %s"%(org.name,self.name))
#	org.sendPublicKey(self)
#
#	#user inputs the username and password that he wants
#	self.username = raw_input("Registration: please enter username: ")
#	password = getpass.getpass("Please enter password: ")
#	self.password_hash = crypto_functions.hash256(password)
#	print("Computing hash of password: %s"%self.password_hash)
#
#	#password is stored as hash for security reasons
#	#user scans his token, and the block id and AES key is encrypted using the public key and sent back to the organization
#	#simulation of virtual token, type in ID number to scan token
#	token = users[raw_input("Please scan your token: ")].token
#	message = "{'request': 'register', 'block_id': '%s', 'username': '%s', 'password_hash': '%s', 'aes_key': %s}" %(token.block_id,self.username, self.password_hash, token.AES_key)
#	print("Encrypting request by user to register for organization: %s"%message)
#	self.sendToOrg(crypto_functions.rsa_encrypt(message,self.registration_key),org)
#	print("Sending encrypted request:%s"%org.recievedMessage)
#	#org decrypts the message with their private key and handles the message
#	#in this case, the user's request is for registration, and that will be done under the handleRequest method of the org
#
#	#store private key, AES key, and user's block id in the token
#	#first get private key as plaintext
#	f = open("privateKey.pem", "a+b")
#	f.write(org.RSA_pvt_key.exportKey('PEM'))
#    f.seek(0)
#    RSA_pvt_key_str = f.read()
#	print("Using RSA private key to decrypt request: %s"%RSA_pvt_key_str)
#	f.close()
#	#delete file after this to prevent key from being stored as a file
#	os.remove("privateKey.pem")
#	decrypted = crypto_functions.rsa_decrypt(org.recievedMessage,org.RSA_pvt_key)
#	user_request = ast.literal_eval(decrypted) #convert message to dict
#	org.handleRequest(user_request)
	
 
#function which encrypts data using AES
def aes_encrypt(data,key):
	#process data to become suitable for encryption by converting to bytes if needed
	if type(data) != bytes:
		data = bytes(data.encode("utf-8"))
		
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB,iv)

	return iv+cipher.encrypt(data)

#function which decrypts data using AES
def aes_decrypt(data,key):
	iv = data[:16]
	cipher = AES.new(key, AES.MODE_CFB, iv)
	decrypted = cipher.decrypt(data[16:]).decode("utf-8")
	return decrypted

#function which encrypts data using RSA
def rsa_encrypt(data, public_key):
	if type(data) != bytes:
		data = bytes(data.encode("utf-8"))
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
	session_key = cipher.decrypt(data[1]).decode("utf-8")
	#then decrypt the data using AES and the session key
	return aes_decrypt(data[0], session_key)


#computes a SHA256 hash of the data
def hash256(data):
	data = bytes(data.encode("utf-8"))
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
    

if __name__ == "__main__":
    app.run()