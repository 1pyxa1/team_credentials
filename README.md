# team_credentials
git team credentials aes storage system

## Usage examples

### Example 1: encrypt_cred
```
from pathlib import Path
from team_credentials.team_credentials import TeamCredentials

tc = TeamCredentials(Path('tc_conf.json'))
dic = {
    'server': {'public': 1, 'value': '192.168.0.1'},
    'port': {'public': 1, 'value': '5432'},
    'db': {'public': 1, 'value': 'example_db'},
    'db_user': {'public': 0, 'value': '1pyxa1'},
    'db_pass': {'public': 0, 'value': 'gOlBjgswe0HvMewrd6DiuoHE97k5'}
    }
team_dic, cred_dic = tc.encrypt_cred('example db conn', dic)
print(team_dic, cred_dic, sep='\n\n')
```

### output:
```
{
    "example db conn": {
        "server": {
            "public": 1,
            "value": {
                "nonce": "BVzk37zfkXdd39GS+e2Lwg==",
                "ciphertext": "aV1AVmB1gY42wouf//pnGho88ouB3A02egyIleRNJKBs/dHAAaGA",
                "tag": "kMDXHl1Nd9GEAPjFicQbEA==",
                "salt": "afZy2mRbfZiw6kLlkryMngIJVcC3heUARv9Z1HFI9Gk="
            }
        },
        "port": {
            "public": 1,
            "value": {
                "nonce": "sj2avP5Z9uPgZAvtsXxrYg==",
                "ciphertext": "tFoKLBvHVdldRdq+T/kzxtCXydnFjknT6F0WG1Sw09c=",
                "tag": "PRBzdMYdG5hIV9qIu95xJg==",
                "salt": "xEabucHEE+QSlqwNkdYuISUxGpKXuw1I8q1B3XnWE5Q="
            }
        },
        "db": {
            "public": 1,
            "value": {
                "nonce": "sWGREBXC0uvrYY6OzVfY8g==",
                "ciphertext": "seRdnV5Ydj8smWXWJDxmPiPG46VV9BbeNmIEt2u3+UgGGXh8rRU=",
                "tag": "NO9vI61qSF4XlMiMVkuzEA==",
                "salt": "Z+QXvVHmxR5/9SMdn2/eVvO1TpL6xv/3H6afcitoEx0="
            }
        },
        "db_user": {
            "public": 0
        },
        "db_pass": {
            "public": 0
        }
    }
}

{
    "example db conn": {
        "db_user": {
            "nonce": "tg0sGBuDf98YwXRCjaCoMg==",
            "ciphertext": "7yEjTgMAGSzvMoSUQHyaHZn6chewFCJLTTJzoCH/TgFKTQA=",
            "tag": "nHV+S4dfl8l/tuW5uBl3Aw==",
            "salt": "h5XgACRcrG0EuiZyBwoeUKlW99TI6LrkQ/Ri1IcsZDM="
        },
        "db_pass": {
            "nonce": "doCiPS7Bn4QxUhOsCV4bHw==",
            "ciphertext": "IKw8Ghd+y4X/zA25uWKs0fy0jI+SDtCM8DZe/1Ft4txUo+zQTvbPcQz8iU/FjEAeVwwYmmsL1KUz",
            "tag": "C0yI5uTy1nsHN4J6hxgftg==",
            "salt": "xrkC6I85laWRGFIQYansZ5prbriDH0jE2uhwulTRu9I="
        }
    }
}
```

### Example 2: encrypt_cred with only_cred=True
```
from pathlib import Path
from team_credentials.team_credentials import TeamCredentials

tc = TeamCredentials(Path('tc_conf.json'))
dic = {
    'db_user': {'public': 0, 'value': 'syshchenko_rv'},
    'db_pass': {'public': 0, 'value': 'rOlBjgRfe0HvM7d6DiuoHE97k55KGwAixSD5obwp'}
    }
cred_dic = tc.encrypt_cred('shiptor repl 106', dic, only_cred=True)
print(cred_dic)
```

### output:
```
{
    "example db conn": {
        "db_user": {
            "nonce": "0OZ9OPbn5PpUONCjikUZWA==",
            "ciphertext": "Vg0meE3WkqOwD/PPXHYwjPHYquNvCy6mgi4FeWYx9QLoaQE=",
            "tag": "4lC1Pc50U2MfyXVeOaXoIw==",
            "salt": "EMN7Wq2k2NQv9QB4LcED4IVhEy6hP3cCzlq207rsPsA="
        },
        "db_pass": {
            "nonce": "1oNCP7YCXZb5bcIHuEjsTA==",
            "ciphertext": "TAJrf2+GuxKRv8kIibNGvURC2bPNsNsBkbDMFk/5hyxGIHM4yBHznKU1LbGp8Io6idiToWPWtTFx",
            "tag": "Del90UtE2aRdjXH/Gokn5w==",
            "salt": "9MTJolWlzlQ4I+QF5N9hmWZDeTutKD4A/XI+VNS1zIU="
        }
    }
}
```

### Example 3: get_credential
```
from team_credentials.team_credentials import TeamCredentials
tc.get_credentials('example db conn', local=True)
```