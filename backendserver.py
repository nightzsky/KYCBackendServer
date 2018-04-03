# -*- coding: utf-8 -*-
"""
Created on Thu Mar 08 20:17:09 2018
@author: Nightzsky
"""


languages = [{'block_id':'user_info'}]

from flask import Flask,jsonify,request,Response
from crypto_functions import *
import base64
import json
import string
import requests
import os
import ast
from functools import wraps
from validity import isValidInput
from flask_basicauth import BasicAuth

app = Flask(__name__)
#
app.config['BASIC_AUTH_USERNAME'] = 'admin'
app.config['BASIC_AUTH_PASSWORD'] = 'secret'

def check_auth(username, password):
    return username == 'admin' and password == 'secret'

def authenticate():
    message = {'message':"Authenticate."}
    
    resp = jsonify(message)
    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm = "Example"'
    
    return resp

def requires_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        auth = request.authorization
        if not auth:
            return authenticate()
        
        elif not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    
    return decorated

@app.route("/")
def receiveInformation():
    return "bye"

@app.route("/lang")
def hello():    
    return jsonify({"languages":languages})

##
# Randomly generates and returns an RSA public-private key pair as strings
##
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
    f.write(RSA_pvt_key.exportKey('PEM', pkcs = 8))
    f.seek(0)
    RSA_pvt_key_str = f.read()
    print("Generating RSA private key: %s"%RSA_pvt_key_str)
    f.close()
    os.remove("privateKey.pem")

    return RSA_pub_key_str,RSA_pvt_key_str

##
# Encrypts a python dictionary using AES and returns it
##
def encrypt_dict(raw, AES_key):
    encrypted = {}
    print("Encrypting user info:%s"%str(raw))
    for key in raw:
        encrypted[key] = aes_encrypt(raw[key], AES_key)
    return encrypted

def get_user_from_blockchain(block_id):
    #get the corresponding encrypted user info from the block
    token = os.environ['BLOCKCHAIN_TOKEN']
    r = requests.get("https://173.193.102.98:31090/api/User/%s?access_token=%s"%(block_id,token), verify = False)
    print(r.status_code)
    print(r.text)
    return r.status_code,json.loads(r.text)

##
# Creates a new user in the hyperledger blockchain
##
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
    r = requests.post("https://173.193.102.98:31090/api/User?access_token=%s"%os.environ['BLOCKCHAIN_TOKEN'], json = payload, verify = False)

    if r.status_code != 200:
        print("Error in creating new user in blockchain: request returned %d"%r.status_code)
        print("Request response: %s"%r.text)
    
    else:
        print("New user %s successfully created in blockchain."%block_id)
        return True

def update_user_blockchain(block_id, encrypted):
    payload = {
            "$class": "org.acme.biznet.updateUserEncryptedData",
            "hashed_id": block_id,
            "newData": {
                    "$class": "org.acme.biznet.UserData",
                    "name": encrypted["name"],
                    "encrypted_id": encrypted["encrypted_id"],
                    "postcode": encrypted["postcode"],
                    "birthdate": encrypted["birthdate"],
                    "merkle_root": encrypted["merkle_root"],
                    "rsa_public_key": encrypted["rsa_public_key"],
                    }
            }
            
    #post it to hyperledger
    r = requests.post("https://173.193.102.98:31090/api/updateUserEncryptedData?access_token=%s"%os.environ['BLOCKCHAIN_TOKEN'], json = payload, verify = False)
    if r.status_code != 200:
        print("Error in updating user in blockchain: request returned %d"%r.status_code)
        print("Request response: %s"%r.text)
    else:
        print("User %s successfully created in blockchain."%block_id)
        return True;
    
##
# This function decrypts an incoming HTTP request using the RSA private key
# All requests will be encrypted using the RSA public key, so all requests will have to be decrypted before they are processed
# Specifically, this function will decrypt the json parameter of the request
##

def decrypt_request(json):
    private_key = os.environ["PRIVATE_KEY"].replace("\\n","\n")
    decrypted = {}
    for key in json:
        if type(json[key]) == dict:
            decrypted[rsa_decrypt(ast.literal_eval(key),private_key)] = decrypt_request(json[key])
        else:
            decrypted[rsa_decrypt(ast.literal_eval(key),private_key)] = rsa_decrypt(ast.literal_eval(json[key]), private_key)

    return decrypted

@app.route("/register_kyc", methods = ['POST'])
@app.required
def register_kyc():  
    #retrieve data 
    print(request.json)
    decrypted = decrypt_request(request.json)
    print(decrypted)

    name = decrypted["name"]
    postal_code = decrypted["postal_code"]
    id_number = decrypted["id_number"]
    dob = decrypted["dob"]

#    if not isValidInput(decrypted):
#        resp = Response(json.dumps({"message":"invalid input"}))
#        resp.status_code = 400
#        return resp
    happy = False
    if(happy):
        name = "hi"
    
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
        new_user_success = new_user_blockchain(block_id, encrypted_user_info)

        #stop execution if user was not successfully created in blockchain
        if not new_user_success:
            resp = Response(json.dumps({"message": "Creating new user on blockchain failed"}))
            resp.status_code = 500
            return resp
        
        #store private key, AES key, and user's block id in the token
        #create the token object, and assign it to the user who is registering
        print("Storing RSA private key, AES key, block ID and information used to compute merkle root in token")
        #generate a token for the user and store the info inside it
        token = {}
        token["private_key"] = RSA_pvt_key_str.decode("utf-8")
        token["AES_key"] = str(list(AES_key))
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
    status_code,encrypted_info = get_user_from_blockchain(block_id)
    
    if (status_code == 200): # if success in retreiving the user info from blockchain
        #post the encrypted user info back to the companybackend
        resp = Response(json.dumps(encrypted_info))
        resp.status_code = 200
        print(resp)
        
        return resp
    
    else: # if fail to retrieve the user_info from blockchain
        resp = Response(json.dumps({"Error":"Failed to retrieve user info/User does not exist."}))
        resp.status_code = 500
        
        return resp

@app.route("/update_token", methods = ['POST'])
def update_token():
    print(request.json)
    decrypted = decrypt_request(request.json)
    print(decrypted)

    old_AES_key = decrypted["AES_key"]
    block_id = decrypted["block_id"]
    
    #get the corresponding encrypted user info from the block
#    token = os.environ['BLOCKCHAIN_TOKEN']
#    r = requests.get("https://173.193.102.98:31090/api/User/%s?access_token=%s"%(block_id,token), verify = False)
#    print("out")
#    print(r.status_code)
#    print(r.text)
    
    status_code,userData = get_user_from_blockchain(block_id)
    if (status_code == 200):  
        userData = userData["userData"]
        del userData["$class"]
        print(userData)
               
        #decrpyt the user data with AES key
        for key in userData:
            print("decrypting %s now"%key)
            userData[key] = aes_decrypt(userData[key],old_AES_key)
        print(userData)
        
        #generate AES key for the user
        new_AES_key = Random.new().read(32)
        print("Generating AES key: %s"%new_AES_key)
        
        encrypted_user_info = encrypt_dict(userData,new_AES_key)
            
        print("Encrypted user info: %s"%str(encrypted_user_info))
        print("Storing encrypted user info in block")
        
        update_user_success = update_user_blockchain(block_id,encrypted_user_info)
        
        if not update_user_success:
            resp = Response(json.dumps({"Error":"Fail to update the blockchain."}))
            resp.status_code = 500
            return resp
        
        resp = Response(json.dumps({"AES_key":str(list(new_AES_key))}))
        resp.status_code = 200
        
        return resp
    else:
        resp = Response(json.dumps({"Error":"Failed to retrieve user data"}))
        resp.status_code = 400
        return resp

 ##
 # This function returns the public key for the KYC backend
 # Anyone can use a GET method on this url to obtain the public key
 # They can then use this public key to encrypt their requests
 ##
@app.route("/getkey", methods = ['GET'])

def get_key():
    return os.environ["PUB_KEY"].replace("\\n","\n")

@app.route("/token_lost",methods = ['POST'])
def token_lost():
    decrypted = decrypt_request(request.json)
    block_id = decrypted["block_id"]
    
    payload = {
        "$class": "org.acme.biznet.revokeAccess",
        "hashed_id": block_id
        } 
    #post it to hyperledger
    r = requests.post("https://173.193.102.98:31090/api/revokeAccess?access_token=%s"%os.environ['BLOCKCHAIN_TOKEN'], json = payload, verify = False)
    print(r.status_code)
    print(r.text)
    
    if (r.status_code == 200):
        resp = Response(json.dumps({"Message":"The access is changed to false"}))
        resp.status_code = 200
        return resp
    
    else:
        resp = Response(json.dumps({"Error":"Failed to revoke access"}))
        resp.status_code = 400
        return resp   
#
#@app.route("/regenerate_token",methods = ['POST'])
#def regenerate_token():
    

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