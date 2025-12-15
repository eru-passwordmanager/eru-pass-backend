from services.crypto.crypto_service import CryptoService, KdfParams

master = "1234"
salt = CryptoService.generate_salt()
params = KdfParams()

key = CryptoService.derive_key(master, salt, params)

enc = CryptoService.encrypt_to_string(key, b'{"u":"a","p":"b"}')
dec = CryptoService.decrypt_from_string(key, enc)

print(enc)
print(dec)