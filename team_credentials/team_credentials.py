from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import json
from Crypto.Protocol.KDF import scrypt
from pathlib import Path
import re
import requests
from typing import Dict


class AesGcm:
    def __init__(self):
        self.json_k = ['nonce', 'ciphertext', 'tag', 'salt']

    def encryption(self, password: str, msg: str) -> str:
        salt = get_random_bytes(32).decode('utf8')
        keys = scrypt(password, salt, key_len=32, N=2**17, r=8, p=1, num_keys=1)

        if not isinstance(keys, bytes):
            key = keys[0]
        else:
            key = keys

        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf8'))
        json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, ciphertext, tag, salt)]
        encrypted_msg = json.dumps(dict(zip(self.json_k, json_v)))
        return encrypted_msg

    def decryption(self, encrypted_msg: str, password: str) -> str:

        b64 = json.loads(encrypted_msg)
        jv = {k: b64decode(b64[k]) for k in self.json_k}

        key = scrypt(password, jv['salt'].decode('utf8'), key_len=32, N=2**17, r=8, p=1)

        cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        return plaintext.decode('utf8')


class TeamCredentials:

    def __init__(self, conf: Path):
        self.conf: Dict[str, str] = {}
        self._read_conf(conf)

        self.aes = AesGcm()

        self.url = self.conf['url']
        self.team_master_password = self.conf['team_master_password']
        self.team_master_salt = self.conf['team_master_salt']
        self.credential = self.conf['credential']
        self.master_password = self.conf['master_password']
        self.master_salt = self.conf['master_salt']

        self.team_json_fn = 'team_credential.json'
        self.url_team = self.url + f'{self.team_json_fn}/raw?ref=master'

        self.cred_json_fn = f'{self.credential}_credential.json'
        self.url_cred = self.url + f'{self.cred_json_fn}/raw?ref=master'

        self.gitlab_personal_token = self.conf['gitlab_personal_token']

    def _read_conf(self, conf: Path):
        with open(conf) as jf:
            self.conf = json.load(jf)

    def create(self):
        pass

    def check(self):
        pass

    def update(self):
        pass

    def bulk_update(self):
        pass

    def delete(self):
        pass

    def _get_credentials(self):
        headers = {"PRIVATE-TOKEN": self.gitlab_personal_token}

        team_resp = requests.get(self.url_team, headers=headers)
        team_resp.raise_for_status()

        cred_resp = requests.get(self.url_cred, headers=headers)
        cred_resp.raise_for_status()

        return team_resp.json(), cred_resp.json()

    def _get_local_credentials(self):
        with open(self.team_json_fn) as fn:
            team_resp = json.load(fn)

        with open(self.cred_json_fn) as fn:
            cred_resp = json.load(fn)

        return team_resp, cred_resp

    def get_credentials(self, cred: str, local: bool = False) -> Dict[str, str]:
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
        if public:
            return self.aes.encryption(self.team_master_password, msg + self.team_master_salt)
        return self.aes.encryption(self.master_password, msg + self.master_salt)

    def decrypt(self, encrypted_msg: str, public: bool = False):
        if public:
            msg = self.aes.decryption(encrypted_msg, self.team_master_password)
            return re.sub(re.escape(self.team_master_salt) + '$', '', msg)

        msg = self.aes.decryption(encrypted_msg, self.master_password)
        return re.sub(re.escape(self.master_salt) + '$', '', msg)

    def get_credentials_backup(self):
        pass
