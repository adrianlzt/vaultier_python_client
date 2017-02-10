#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2017 Adrián López Tejedor <adrianlzt@gmail.com>
#
# Distributed under terms of the GNU GPLv3 license.

"""
Python client for Vaultier
"""

import binascii
import hashlib
from base64 import b64decode

import requests
from pkcs7 import PKCS7Encoder
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as PKCS_sign
from Crypto.Hash import SHA

MODE = AES.MODE_CBC

class DataCypher(object):
    def __init__(self, key):
        """
        Acepta una clave en formato string
        """
        self.key = key

    def evpKDF(self, passwd, salt, key_size=8, iv_size=4, iterations=1, hash_algorithm="md5"):
        """
        https://github.com/Shani-08/ShaniXBMCWork2/blob/master/plugin.video.serialzone/jscrypto.py
        """
        target_key_size = key_size + iv_size
        derived_bytes = b''
        number_of_derived_words = 0
        block = None
        hasher = hashlib.new(hash_algorithm)
        while number_of_derived_words < target_key_size:
            if block is not None:
                hasher.update(block)

            hasher.update(passwd)
            hasher.update(salt)
            block = hasher.digest()
            hasher = hashlib.new(hash_algorithm)

            for i in range(1, iterations):
                hasher.update(block)
                block = hasher.digest()
                hasher = hashlib.new(hash_algorithm)

            derived_bytes += block[0: min(len(block), (target_key_size - number_of_derived_words) * 4)]

            number_of_derived_words += len(block)/4

        return {
            "key": derived_bytes[0: key_size * 4],
            "iv": derived_bytes[key_size * 4:]
        }

    def encrypt(self, plaintext):
        salt = Random.new().read(8)
        resp = self.evpKDF(self.key, salt, key_size=12)
        key = resp.get("key")
        iv = key[len(key)-16:]
        key = key[:len(key)-16]

        aes = AES.new(key, MODE, iv)
        encoder = PKCS7Encoder()
        pad_text = encoder.encode(plaintext)
        encrypted_text = aes.encrypt(pad_text)

        return binascii.b2a_base64(concat).rstrip()

    def decrypt(self, encrypted_text):
        encrypted_text_bytes = binascii.a2b_base64(encrypted_text)

        # Remove "Salt__"
        encrypted_text_bytes = encrypted_text_bytes[8:]

        # Get and remove salt
        salt = encrypted_text_bytes[:8]
        encrypted_text_bytes = encrypted_text_bytes[8:]

        resp = self.evpKDF(self.key, salt, key_size=12)
        key = resp.get("key")
        iv = key[len(key)-16:]
        key = key[:len(key)-16]

        aes = AES.new(key, MODE, iv)
        decrypted_text = aes.decrypt(encrypted_text_bytes)
        encoder = PKCS7Encoder()
        unpad_text = encoder.decode(decrypted_text.decode('utf-8'))

        return unpad_text

class WorkSpaceCypher(object):
    def __init__(self, priv_key=None, pub_key=None):
        """
        priv_key: texto ascii con la clave privada
        pub_key: texto ascii con la clave publica
        """
        if priv_key:
            self.set_priv_key(priv_key)
        if pub_key:
            self.set_pub_key(pub_key)

    def set_priv_key(self, priv_key):
        key = RSA.importKey(priv_key)
        self.priv = PKCS1_v1_5.new(key)
        self.priv_sign = PKCS_sign.new(key)

    def set_pub_key(self, pub_key):
        key = RSA.importKey(pub_key)
        self.pub = PKCS1_v1_5.new(key)
        self.pub_sign = PKCS_sign.new(key)

    def sign(self, text):
        signed = self.priv_sign.sign(text)
        return signed

    def verify(self, text, sign):
        verify = self.pub_sign.verify(text, sign)
        return verify

    def encrypt(self, text):
        """
        Retorna una string en base64 de los datos codificados
        """
        crypted = self.pub.encrypt(text)
        crypted_b64 = binascii.b2a_base64(crypted)
        return crypted_b64

    def decrypt(self, base64_text):
        """
        Retorna una string con el texto desencryptado
        """
        raw_cipher_data = binascii.a2b_base64(base64_text)
        try:
            decrypted = self.priv.decrypt(raw_cipher_data,'')
        except ValueError as ex:
            if ex.message == "Message too large":
                raise Exception("Parece que no estas usando la clave privada adecuada")
            raise ex
        return decrypted

if __name__ == "__main__":
    # Datos
    email = "some@one.com"
    server = "https://example.com/api"
    priv_key = "vaultier.key" # Fichero donde esta la clave privada
    pub_key = "vaultier.key.pub" # TODO: No es necesaria, nos la da el server


    # Creamos el cypher con nuestras claves publica y privada
    # Esto se usara para encriptar/desencriptar la clave maestra de los workspaces
    priv = open(priv_key, "r").read()
    pub = open(pub_key, "r").read()
    wc = WorkSpaceCypher(priv, pub)

    server_time = requests.get("%s/server-time/" % server, verify=False)
    date = server_time.json().get("datetime")

    h = SHA.new(str(email + date).encode('utf-8'))
    signature = wc.sign(h)
    signature_b64 = binascii.b2a_base64(signature)

    # Post
    data = {
        "email": email,
        "date": date,
        "signature": signature_b64
    }
    login_post = requests.post("%s/auth/auth" % server, data=data, verify=False)
    resp_json = login_post.json()
    user_id = resp_json.get("user")
    token = resp_json.get("token")

    headers = {"X-Vaultier-Token": token}

    # Get my user
    reps_my_user_data = requests.get("%s/users/%s/" % (server,user_id), verify=False, headers=headers)
    my_user_data = reps_my_user_data.json()
    public_key = my_user_data.get("public_key")
    nickname = my_user_data.get("nickname")

    # Get my workspaces
    workspaces_deciphers = {}

    resp_workspaces = requests.get("%s/workspaces/" % server, verify=False, headers=headers)
    workspaces = resp_workspaces.json()
    for w in workspaces:
        id = w.get("id")
        slug = w.get("slug")
        print("id:%s  slug:%s" %(id, slug))
        workspace_key = w.get("membership").get("workspace_key")
        decrypted_key = wc.decrypt(workspace_key)
        dc = DataCypher(decrypted_key)
        workspaces_deciphers.update({w.get("slug"): dc})

    # Get last workspace
    print("Opening workspace %s" % slug)
    resp_vaults = requests.get("%s/vaults/?workspace=%s" % (server,id), verify=False, headers=headers)
    vaults = resp_vaults.json()
    for v in vaults:
        id = v.get("id")
        slug = v.get("slug")
        print("Vault (%s) slug: %s" % (id,slug))

    # Get cards from last vault
    print("Opening card %s" % slug)
    resp_cards = requests.get("%s/cards/?vault=%s" % (server,id), verify=False, headers=headers)
    cards = resp_cards.json()
    for c in cards:
        id = c.get("id")
        slug = c.get("slug")
        print("Card (%s) slug: %s" % (id,slug))

    # Get last card
    resp_card = requests.get("%s/secrets/?card=%s" % (server,id), verify=False, headers=headers)
    card = resp_card.json()
    for secret in card:
        print("Secret name: %s" % secret.get("name"))
        data_encrypted = secret.get("data")
        secret = workspaces_deciphers.get("dsmc-tools-3").decrypt(data_encrypted)
        print("Secret: %s" % secret)

