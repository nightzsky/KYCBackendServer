# -*- coding: utf-8 -*-
"""
Created on Thu Mar 08 20:17:09 2018

@author: Nightzsky
"""


languages = [{'block_id':'user_info'}]
users = {}
orgs = {}

from flask import Flask,jsonify,request,Response
#from __future__ import print_function
#import sys
#import demo
from crypto_functions import *
import base64
import json
import string
import requests
import os
import ast
from functools import wraps
from validity import isValidInput
app = Flask(__name__)


@app.route("/")
def receiveInformation():
    return "bye"

@app.route("/lang")
def hello():    
    return jsonify({"languages":languages})

#Randomly generates and returns an RSA public-private key pair as strings
def generate_rsa_key_pair():
    RSA_pvt_key = RSA.generate(2048)
    RSA_pub_key = RSA_pvt_key.publickey()

    #write key to a file then read the same file to obtain the key in plaintext
    f = open("publicKey.pem", "a+b")
    f.write(RSA_pub_key.exportKey('PEM'))
    f.seek(0)
    RSA_pub_key_str = f.read()
    print("Generating RSA public key: %s"%RSA_pub_key_str)
    f.close()
    #delete file after this to prevent key from being stored as a file
    os.remove("publicKey.pem")

    #Do the same for private key
    f = open("privateKey.pem", "a+b")
    f.write(RSA_pvt_key.exportKey('PEM'))
    f.seek(0)
    RSA_pvt_key_str = f.read()
    print("Generating RSA private key: %s"%RSA_pvt_key_str)
    f.close()
    os.remove("privateKey.pem")

    return RSA_pub_key_str,RSA_pvt_key_str

#Encrypts a python dictionary using AES and returns it
def encrypt_dict(raw, AES_key):
    encrypted = {}
    print("Encrypting user info:%s"%str(raw))
    for key in raw:
        encrypted[key] = aes_encrypt(raw[key], AES_key)
    return encrypted

#Creates a new user in the hyperledger blockchain
def new_user_blockchain(block_id, encrypted_info):
    payload = {
      "$class": "org.acme.biznet.User",
      "hashed_id": block_id,
      "userData": {
        "$class": "org.acme.biznet.UserData",
        "name": encrypted_info["name"],
        "encrypted_id": encrypted_info["id_number"],
        "postcode": encrypted_info["postal_code"],
        "birthdate": encrypted_info["dob"],
        "merkle_root": encrypted_info["merkle"],
        "rsa_public_key": encrypted_info["public_key"]
      },
      "access": True
    }
      
    #post it to hyperledger      
    r = requests.post("http://173.193.102.98:31090/api/User?access_token=IAKxrB59D9QWATWgBJqhJNK6f4rUEBu1YLjBjewoyOu8Ri6fE78OcnsFhFiM1qmX", json = payload)

    if r.status_code != 200:
        print("Error in creating new user in blockchain: request returned %d"%r.status_code)
        print("Request response: %s"%r.text)
    
    else:
        print("New user %s successfully created in blockchain."%block_id)


@app.route("/register_kyc", methods = ['POST'])
def register_kyc():  
    #retrieve data
    name = request.json["name"]
    postal_code = request.json["postal_code"]
    id_number = request.json["id_number"]
    dob = request.json["dob"]
    
    #check if the info is valid
    if not isValidInput(request.json):
        resp = Response(json.dumps({"message":"invalid input"}))
        resp.status_code = 400
        return resp
    
    else:
        #create a new dictionary for user_info
        user_info = {}  
        user_info["name"] = name
        user_info["postal_code"] = postal_code       
        user_info["id_number"] = id_number
        user_info["dob"] = dob
        
        #generate AES key for the user
        AES_key = Random.new().read(32)
        print("Generating AES key: %s"%AES_key)
        
        #generate RSA key pairs for the user
        RSA_pub_key_str, RSA_pvt_key_str = generate_rsa_key_pair()    
            
        #create Merkle tree hash from user information, and add it to the dictionary
        merkle_raw = user_info.copy().values() #make a copy of the information used to create the merkle tree 
        hashed_info = [hash256(item) for item in merkle_raw]
        merkles = merkle(hashed_info)
        print("Computed merkle root: %s"%merkles)
        print("Storing merkle root in user info")
        #add the merkle to the user info
        user_info["merkle"] = merkles
            
        
        print("Storing RSA public key in user info")
        #add the public key to the user info
        user_info["public_key"] = RSA_pub_key_str
        encrypted_user_info = encrypt_dict(user_info,AES_key)
        
        print("Encrypted user info: %s"%str(encrypted_user_info))
        print("Storing encrypted user info in block")
        
        #get block id for hyperledger for user, post to hyperledger
        block_id = hash256(user_info["id_number"])
        new_user_blockchain(block_id, encrypted_user_info)
        
        #store private key, AES key, and user's block id in the token
       
        #create the token object, and assign it to the user who is registering
        print("Storing RSA private key, AES key, block ID and information used to compute merkle root in token")
        #generate a token for the user and store the info inside it
        token = {}
        token["private_key"] = RSA_pvt_key_str.decode("utf-8")
        token["AES_key"] = AES_key.decode("cp437")
        token["block_id"] = block_id
        token["merkle_raw"] = merkles
            
        print(token)
            
        #send back to the user
        resp = Response(json.dumps(token))
        resp.status_code = 200
        print(resp)
            
         
        print("received data")
            
        languages.append(user_info)
        return resp

@app.route("/register_org", methods=['POST'])
def register_org():
    #receive block_id sent from the company
    block_id = request.json["block_id"]
    
    #get the corresponding encrypted user info from the block
    r = requests.get("http://173.193.102.98:31090/api/User/%s?access_token=IAKxrB59D9QWATWgBJqhJNK6f4rUEBu1YLjBjewoyOu8Ri6fE78OcnsFhFiM1qmX"%block_id)
    print(r.status_code)
    print(r.text)
    
    #post the encrypted user info back to the companybackend
    resp = Response(json.dumps(json.loads(r.text)))
    resp.status_code = 200
    print(resp)
    
    return resp

 






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