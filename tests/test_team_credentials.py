from team_credentials.team_credentials import AesGcm, TeamCredentials
import pytest


def test_tc_docstring():
    assert len(TeamCredentials.__doc__) > 10


def test_aes_class_module_docstring():
    assert len(AesGcm.__doc__) > 10


def test_aes_encryption():

    aes = AesGcm()
    pass_ = 'secret_password'
    msg = 'secret msg'
    encrypted_msg = aes.encryption(pass_, msg)
    assert msg == aes.decryption(pass_, encrypted_msg)

    pass_ = 's'
    msg = 's'
    encrypted_msg = aes.encryption(pass_, msg)
    assert msg == aes.decryption(pass_, encrypted_msg)

    pass_ = ''
    msg = ''
    encrypted_msg = aes.encryption(pass_, msg)
    assert msg == aes.decryption(pass_, encrypted_msg)

    with pytest.raises(TypeError):
        encrypted_msg = aes.encryption(1, '1')

    with pytest.raises(TypeError):
        encrypted_msg = aes.encryption('1', 1)

    with pytest.raises(TypeError):
        encrypted_msg = aes.decryption(1, '1')

    with pytest.raises(TypeError):
        encrypted_msg = aes.decryption('1', 1)
