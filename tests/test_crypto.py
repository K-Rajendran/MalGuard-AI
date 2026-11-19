import io
import pytest
import pyAesCrypt
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from malguard.crypto import encrypt,decrypt
from malguard.core import AnalysisError


@pytest.mark.parametrize('data',[b'',b'hello world',bytes(range(256))*100])
@pytest.mark.parametrize('algorithm',['AES-GCM','AES Crypt (legacy)','DES (legacy)'])
def test_round_trip(data,algorithm):
    cipher = encrypt(data,'password',algorithm)
    assert cipher != data
    assert decrypt(cipher,'password','DES (legacy)' if algorithm.startswith('DES') else 'Auto AES') == data


def test_aes_nonces_and_authentication():
    first,second = encrypt(b'private','long passphrase'),encrypt(b'private','long passphrase')
    assert first != second
    for data,password in [(first,'wrong'),(first[:-1],'long passphrase'),(first[:-1]+bytes([first[-1]^1]),'long passphrase')]:
        with pytest.raises(AnalysisError): decrypt(data,password)


def test_original_aescrypt_compatibility():
    output = io.BytesIO()
    pyAesCrypt.encryptStream(io.BytesIO(b'Original AES workflow'),output,'secret',65536)
    assert decrypt(output.getvalue(),'secret') == b'Original AES workflow'


def test_original_des_key_padding_compatibility():
    original = DES.new('abc'[:8].ljust(8,'0').encode(),DES.MODE_ECB).encrypt(pad(b'Original DES workflow',8))
    assert decrypt(original,'abc','DES (legacy)') == b'Original DES workflow'
    assert encrypt(b'Original DES workflow','abc','DES (legacy)') == original


@pytest.mark.parametrize('password',['','éééééééé'])
def test_invalid_des_key(password):
    with pytest.raises(AnalysisError): encrypt(b'x',password,'DES (legacy)')


@pytest.mark.parametrize('data',[b'',b'pickle data',b'AES',b'MG-AES-GCM\x01'])
def test_bad_ciphertext(data):
    with pytest.raises(AnalysisError): decrypt(data,'secret')
