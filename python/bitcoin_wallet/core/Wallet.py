from bitcoin_wallet.database.models import WalletDB, AddressDB
from bitcoin_wallet.utils.crypto.keys import HDKeys
from bitcoin_wallet.utils.crypto.security import Security
from dotenv import load_dotenv

import os
import requests

load_dotenv()

CYPHER_BASE_URL = os.getenv("CYPHER_BASE_URL")

class Wallet:
    def __init__(self, wallet_db: WalletDB, address_db: AddressDB):
        self.wallet_db = wallet_db
        self.address_db = address_db
        self.hd_keys = HDKeys(None)
        self.security = Security()

    
    def create_new_wallet(self, name: str, password: str):
        # Generate a new mnemonic phrase
        mnemonic_phrase = self.hd_keys.generate_mnemonic()
        seed = self.hd_keys.generate_seed_from_mnemonic(mnemonic_phrase)

        # Encrypt the mnemonic phrase
        encrypted_data = self.security.encrypt_mnemonic(mnemonic_phrase, password)

        # Store the encrypted mnemonic and related data in the database
        wallet_id = self.wallet_db.create_wallet(
            name=name,
            encrypted_mnemonic=encrypted_data['encrypted_mnemonic'],
            seed=seed,
            kdf=encrypted_data['kdf'],
            kdf_salt=encrypted_data['kdf_salt'],
            kdf_params=encrypted_data['kdf_params'],
            enc_nonce=encrypted_data['enc_nonce'],
            version=encrypted_data['version']
        )

        return wallet_id, mnemonic_phrase, seed
    
    def generate_new_address(self, wallet_id: int, password: str, change: bool, address_type: str='P2PKH', account_idx: int=0):
        wallet_data = self.get_wallet_by_id(wallet_id=wallet_id)
        if not wallet_data:
            raise ValueError("Wallet ID is invalid")

        # Decrypt the mnemonic phrase
        mnemonic_phrase = self.security.decrypt_mnemonic(
            encrypted_blob=wallet_data["encrypted_mnemonic"],
            password=password
        )

        hd_keys_seed = self.hd_keys.generate_seed_from_mnemonic(mnemonic_phrase)

        # Generate the address
        address_idx = self.address_db.get_next_address_index(wallet_id=wallet_id)
        address = self.hd_keys.generate_bip44_address(hd_keys_seed, account_idx, change, address_idx)

        # Store the address in the database
        derivation_path = f"m/44'/0'/{account_idx}'/{int(change)}/{address_idx}"
        self.address_db.create_address(
            wallet_id=wallet_id,
            address=address,
            address_type=address_type,
            index_num=address_idx,
            derivation_path=derivation_path,
            is_change=change,
            is_used=False
        )

        print(f"Successfully generated address: {address}")

        return address
    
    def get_wallet_from_seed(self, seed: str):
        data = self.wallet_db.get_wallet_from_seed(seed=seed)

        return data
    
    def get_wallet_by_id(self, wallet_id: int):
        data = self.wallet_db.get_wallet(wallet_id=wallet_id)

        return data
    
    def get_balance_from_address(self, address: str, testnet: bool=True, unspent: bool=True):
        if testnet:
            url = CYPHER_BASE_URL + "test3/" + address + f"?unspentOnly={unspent}"
        else:
            url = CYPHER_BASE_URL + "main/" + address + f"?unspentOnly={unspent}"

        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        return data
    
    def send_bitcoin(self):
        ...

    