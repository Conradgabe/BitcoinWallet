from python.bitcoin_wallet.database.models import WalletDB, AddressDB
from python.bitcoin_wallet.utils.crypto.keys import HDKeys
from python.bitcoin_wallet.utils.crypto.security import Security

import os
import requests



class Wallet:
    def __init__(self, wallet_db: WalletDB, address_db: AddressDB, network: str="testnet"):
        self.wallet_db = wallet_db
        self.address_db = address_db
        self.hd_keys = HDKeys(None)
        self.security = Security()
        self.network = network

    def _get_base_url(self):
        base = "https://api.blockcypher.com/v1/btc"
        return f"{base}/test3/addrs" if self.network == "testnet" else f"{base}/main/addrs"


    
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
            kdf=encrypted_data['kdf'],
            kdf_salt=encrypted_data['kdf_salt'],
            kdf_params=encrypted_data['kdf_params'],
            enc_nonce=encrypted_data['enc_nonce'],
            version=encrypted_data['version']
        )

        return {
                "wallet_id": wallet_id,
                "mnemonic": mnemonic_phrase,
                "seed": seed
            }

    
    def generate_new_address(self, wallet_id: int, password: str, change: bool, address_type: str='P2PKH', account_idx: int=0):

        #TODO: Check if the password is valid later

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
        coin_type = 1 if self.network == 'testnet' else 0
        derivation_path = f"m/44'/{coin_type}'/{account_idx}'/{int(change)}/{address_idx}"
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

        return {
                "address": address,
                "derivation_path": derivation_path,
                "index": address_idx
            }

    
    def get_wallet_from_seed(self, seed: str):
        data = self.wallet_db.get_wallet_from_seed(seed=seed)

        return data
    
    def get_wallet_by_id(self, wallet_id: int):
        data = self.wallet_db.get_wallet(wallet_id=wallet_id)

        return data
    
    def get_balance_from_address(self, address: str, unspent: bool=True):
        url = f"{self._get_base_url()}{address}?unspentOnly={str(unspent).lower()}"
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            data = response.json()

            return data
        except requests.RequestException as e:
            print(f"Error fetching balance for {address}: {e}")
            return None
    
    def send_bitcoin(self):
        ...

    