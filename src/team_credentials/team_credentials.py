'''
Main module contains TeamCredentials class
'''

import json
import re
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Dict, Union

import requests
from Crypto.Cipher import AES, _mode_gcm
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


class AesGcm:
    '''
    AES GCM class for encryption and decryption messages
    '''
    def __init__(self):
        self.json_k = ['nonce', 'ciphertext', 'tag', 'salt']

    def encryption(self, password: str, msg: str) -> str:
        '''
        Encrypts message using AES GCM with specified password and random salt
        '''
        salt = get_random_bytes(32)
        key = scrypt(
            password, b64encode(salt).decode('utf8'), key_len=32, N=2**17, r=8, p=1, num_keys=1)
        if not isinstance(key, bytes):
            raise TypeError

        cipher = AES.new(key, AES.MODE_GCM)
        if not isinstance(cipher, _mode_gcm.GcmMode):
            raise TypeError

        ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf8'))

        json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, ciphertext, tag, salt)]

        encrypted_msg = json.dumps(dict(zip(self.json_k, json_v)))
        return encrypted_msg

    def decryption(self, password: str, encrypted_msg: str) -> str:
        '''
        Decrypts encrypted message using AES GCM with specified password
        '''

        b64 = json.loads(encrypted_msg)
        json_v = {}
        for key in self.json_k:
            if key == 'salt':
                json_v[key] = b64[key]
            else:
                json_v[key] = b64decode(b64[key])

        key = scrypt(password, json_v['salt'], key_len=32, N=2**17, r=8, p=1, num_keys=1)
        if not isinstance(key, bytes):
            raise TypeError

        cipher = AES.new(key, AES.MODE_GCM, nonce=json_v['nonce'])
        if not isinstance(cipher, _mode_gcm.GcmMode):
            raise TypeError

        plaintext = cipher.decrypt_and_verify(json_v['ciphertext'], json_v['tag'])
        return plaintext.decode('utf8')


class TeamCredentials:
    '''
    Main class for team_credentials - git team credentials aes storage system
    '''
    def __init__(self, conf: Path):
        self.conf: Dict[str, str] = {}
        self._read_conf(conf)

        self.aes = AesGcm()

        self.team_json_fn = 'team_credential.json'
        self.url_team = self.conf['url'] + f'{self.team_json_fn}/raw?ref=master'

        self.cred_json_fn = f'{self.conf["credential"]}_credential.json'
        self.url_cred = self.conf['url'] + f'{self.cred_json_fn}/raw?ref=master'

        self.gitlab_personal_token = self.conf['gitlab_personal_token']

    def _read_conf(self, conf: Path):
        with open(conf) as json_f:
            self.conf = json.load(json_f)

    def check(self):
        '''
        Compares team (master) credential json with specified personal credential json.
        '''

    def _get_credentials(self):
        headers = {"PRIVATE-TOKEN": self.gitlab_personal_token}

        team_resp = requests.get(self.url_team, headers=headers)
        team_resp.raise_for_status()

        cred_resp = requests.get(self.url_cred, headers=headers)
        cred_resp.raise_for_status()

        return team_resp.json(), cred_resp.json()

    def _get_local_credentials(self):
        with open(self.team_json_fn) as file_n:
            team_resp = json.load(file_n)

        with open(self.cred_json_fn) as file_n:
            cred_resp = json.load(file_n)

        return team_resp, cred_resp

    def get_credentials(self, cred: str, local: bool = False) -> Dict[str, str]:
        '''
        Get credentials from gitlab or local folder
        '''
        if local:
            team_json, cred_json = self._get_local_credentials()
        else:
            team_json, cred_json = self._get_credentials()

        cred_dict = {}
        for key, value in team_json[cred].items():
            if value['public'] == 1:
                cred_dict[key] = self.decrypt(json.dumps(value['value']), True)
            else:
                cred_dict[key] = self.decrypt(json.dumps(cred_json[cred][key]), False)
        return cred_dict

    def encrypt(self, msg: str, public: bool = False):
        '''
        Encrypts message using conf.json with specified passwords
        '''
        if public:
            return self.aes.encryption(
                self.conf['team_master_password'], msg + self.conf['team_master_salt'])
        return self.aes.encryption(self.conf['master_password'], msg + self.conf['master_salt'])

    def encrypt_cred(
            self,
            cred: str,
            dict_msg: Dict[str, Dict[str, Union[str, int]]],
            only_cred: bool = False
            ) -> Union[tuple, str]:
        '''
        Encrypts credential dict using conf.json with specified passwords
        '''
        team_dic: Dict[str, Dict[str, Dict[str, Union[str, int]]]] = {cred: {}}
        cred_dic: Dict[str, Dict[str, Dict[str, Union[str, int]]]] = {cred: {}}

        for key, val in dict_msg.items():
            if not isinstance(val['value'], str):
                raise TypeError

            if val['public'] == 1 and only_cred is False:
                team_dic[cred][key] = {'public': 1}
                team_dic[cred][key]['value'] = json.loads(self.encrypt(val['value'], public=True))
            elif val['public'] == 0:
                team_dic[cred][key] = {'public': 0}
                cred_dic[cred][key] = json.loads(self.encrypt(val['value'], public=False))

        if only_cred:
            return json.dumps(cred_dic, indent=4)
        return json.dumps(team_dic, indent=4), json.dumps(cred_dic, indent=4)

    def decrypt(self, encrypted_msg: str, public: bool = False):
        '''
        Decrypts message using conf.json with specified passwords
        '''
        if public:
            msg = self.aes.decryption(self.conf['team_master_password'], encrypted_msg)
            return re.sub(re.escape(self.conf['team_master_salt']) + '$', '', msg)

        msg = self.aes.decryption(self.conf['master_password'], encrypted_msg)
        return re.sub(re.escape(self.conf['master_salt']) + '$', '', msg)
