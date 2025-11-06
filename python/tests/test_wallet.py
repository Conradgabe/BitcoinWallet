import pytest
import json
import requests
from unittest.mock import MagicMock, patch
from python.bitcoin_wallet.core.Wallet import Wallet


# ---------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------
@pytest.fixture
def mock_wallet_db():
    """Mock for WalletDB."""
    return MagicMock()

@pytest.fixture
def mock_address_db():
    """Mock for AddressDB."""
    return MagicMock()

@pytest.fixture
def mock_wallet_deps(mock_wallet_db, mock_address_db):
    """Combined fixture to easily get wallet + db mocks."""
    wallet = Wallet(mock_wallet_db, mock_address_db, network="testnet")
    return wallet, mock_wallet_db, mock_address_db


# ---------------------------------------------------------------------
# TEST: _get_base_url
# ---------------------------------------------------------------------
def test_get_base_url_returns_correct_value(mock_wallet_deps):
    wallet, _, _ = mock_wallet_deps

    assert wallet._get_base_url() == "https://api.blockcypher.com/v1/btc/test3/addrs"

    wallet.network = "mainnet"
    assert wallet._get_base_url() == "https://api.blockcypher.com/v1/btc/main/addrs"


# ---------------------------------------------------------------------
# TEST: create_new_wallet
# ---------------------------------------------------------------------
@patch("python.bitcoin_wallet.core.Wallet.HDKeys")
@patch("python.bitcoin_wallet.core.Wallet.Security")
def test_create_new_wallet_generates_and_saves(mock_security, mock_hdkeys, mock_wallet_db, mock_address_db):
    """Tests that creating a new wallet encrypts and stores properly."""
    # Mock HDKeys behavior
    mock_hdkeys.return_value.generate_mnemonic.return_value = "test mnemonic"
    mock_hdkeys.return_value.generate_seed_from_mnemonic.return_value = b"seedbytes"

    # Mock Security behavior
    mock_security.return_value.encrypt_mnemonic.return_value = {
        "encrypted_mnemonic": b"ciphertext",
        "kdf": "argon2id",
        "kdf_salt": b"salt",
        "kdf_params": {"time": 2, "mem": 1024},
        "enc_nonce": b"nonce",
        "version": 1
    }

    mock_wallet_db.create_wallet.return_value = 1

    # Instantiate Wallet after patching
    wallet = Wallet(mock_wallet_db, mock_address_db, network="testnet")

    result = wallet.create_new_wallet("TestWallet", "password123")

    assert result["wallet_id"] == 1
    assert result["mnemonic"] == "test mnemonic"
    assert result["seed"] == b"seedbytes"
    mock_wallet_db.create_wallet.assert_called_once()


# ---------------------------------------------------------------------
# TEST: generate_new_address
# ---------------------------------------------------------------------
@patch("python.bitcoin_wallet.core.Wallet.HDKeys")
@patch("python.bitcoin_wallet.core.Wallet.Security")
def test_generate_new_address_success(mock_security, mock_hdkeys, mock_wallet_db, mock_address_db):
    """Tests that new addresses are generated correctly."""
    wallet = Wallet(mock_wallet_db, mock_address_db, network="testnet")

    mock_wallet_db.get_wallet.return_value = {
        "encrypted_mnemonic": {
            "encrypted_mnemonic": b"ciphertext",
            "kdf": "argon2id",
            "kdf_salt": b"salt",
            "kdf_params": json.dumps({"time": 2, "mem": 1024}),
            "enc_nonce": b"nonce",
            "version": 1
        }
    }

    mock_security.return_value.decrypt_mnemonic.return_value = "test mnemonic"
    mock_hdkeys.return_value.generate_seed_from_mnemonic.return_value = b"seedbytes"
    mock_address_db.get_next_address_index.return_value = 0
    mock_hdkeys.return_value.generate_bip44_address.return_value = "tb1qexampleaddress"

    result = wallet.generate_new_address(wallet_id=1, password="password123", change=False)

    assert result["address"] == "tb1qexampleaddress"
    assert "derivation_path" in result
    assert result["index"] == 0
    mock_address_db.create_address.assert_called_once()


# ---------------------------------------------------------------------
# TEST: get_wallet_by_id
# ---------------------------------------------------------------------
def test_get_wallet_by_id(mock_wallet_deps):
    """Tests retrieval of a wallet by ID."""
    wallet, mock_wallet_db, _ = mock_wallet_deps

    mock_wallet_db.get_wallet.return_value = {"wallet_id": 123}
    result = wallet.get_wallet_by_id(123)

    assert result["wallet_id"] == 123
    mock_wallet_db.get_wallet.assert_called_once_with(wallet_id=123)


# ---------------------------------------------------------------------
# TEST: get_balance_from_address
# ---------------------------------------------------------------------
@patch("python.bitcoin_wallet.core.Wallet.requests.get")
def test_get_balance_from_address_success(mock_get, mock_wallet_deps):
    """Tests that get_balance_from_address returns proper balance data."""
    wallet, _, _ = mock_wallet_deps

    mock_response = MagicMock()
    mock_response.json.return_value = {"balance": 1000}
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    result = wallet.get_balance_from_address("tb1qabc123")
    assert result == {"balance": 1000}


@patch("python.bitcoin_wallet.core.Wallet.requests.get")
def test_get_balance_from_address_handles_exception(mock_get, mock_wallet_deps):
    """Tests that get_balance_from_address handles request exceptions."""
    wallet, _, _ = mock_wallet_deps

    mock_get.side_effect = requests.RequestException("Network error")
    result = wallet.get_balance_from_address("tb1qexampleaddress")

    assert result is None
    mock_get.assert_called_once()
