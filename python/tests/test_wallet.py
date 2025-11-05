import pytest
from unittest.mock import MagicMock, patch
from python.bitcoin_wallet.core.Wallet import Wallet

@pytest.fixture
def mock_wallet_deps():
    """Fixture to mock all external dependencies of Wallet class."""
    mock_wallet_db = MagicMock()
    mock_address_db = MagicMock()
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
@patch("bitcoin_wallet.wallet.HDKeys")
@patch("bitcoin_wallet.wallet.Security")
def test_create_new_wallet_generates_and_saves(mock_security, mock_hdkeys, mock_wallet_deps):
    wallet, mock_wallet_db, _ = mock_wallet_deps

    # Mock HDKeys and Security methods
    mock_hdkeys_instance = mock_hdkeys.return_value
    mock_security_instance = mock_security.return_value

    mock_hdkeys_instance.generate_mnemonic.return_value = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    mock_hdkeys_instance.generate_seed_from_mnemonic.return_value = b"seedbytes"
    mock_security_instance.encrypt_mnemonic.return_value = {
        "encrypted_mnemonic": b"ciphertext",
        "kdf": "argon2id",
        "kdf_salt": b"salt",
        "kdf_params": {"time": 2, "mem": 1024},
        "enc_nonce": b"nonce",
        "version": 1
    }

    mock_wallet_db.create_wallet.return_value = 42

    result = wallet.create_new_wallet("Test Wallet", "password123")

    assert result["wallet_id"] == 42
    assert result["mnemonic"].startswith("abandon")
    assert result["seed"] == b"seedbytes"

    mock_wallet_db.create_wallet.assert_called_once()
    mock_security_instance.encrypt_mnemonic.assert_called_once_with(result["mnemonic"], "password123")


# ---------------------------------------------------------------------
# TEST: generate_new_address
# ---------------------------------------------------------------------
@patch("bitcoin_wallet.wallet.HDKeys")
@patch("bitcoin_wallet.wallet.Security")
def test_generate_new_address_success(mock_security, mock_hdkeys, mock_wallet_deps):
    wallet, mock_wallet_db, mock_address_db = mock_wallet_deps

    # Mock DB
    mock_wallet_db.get_wallet.return_value = {
        "encrypted_mnemonic": b"encrypted-data"
    }

    mock_address_db.get_next_address_index.return_value = 5
    mock_address_db.create_address.return_value = 99

    # Mock HDKeys and Security
    mock_security_instance = mock_security.return_value
    mock_security_instance.decrypt_mnemonic.return_value = "abandon abandon ..."

    mock_hdkeys_instance = mock_hdkeys.return_value
    mock_hdkeys_instance.generate_seed_from_mnemonic.return_value = b"seedbytes"
    mock_hdkeys_instance.generate_bip44_address.return_value = "tb1qexampleaddress"

    result = wallet.generate_new_address(wallet_id=1, password="pass", change=False)

    assert result["address"] == "tb1qexampleaddress"
    assert "derivation_path" in result
    assert "index" in result

    mock_wallet_db.get_wallet.assert_called_once_with(wallet_id=1)
    mock_security_instance.decrypt_mnemonic.assert_called_once()
    mock_hdkeys_instance.generate_bip44_address.assert_called_once()


# ---------------------------------------------------------------------
# TEST: get_wallet_by_id
# ---------------------------------------------------------------------
def test_get_wallet_by_id(mock_wallet_deps):
    wallet, mock_wallet_db, _ = mock_wallet_deps

    mock_wallet_db.get_wallet.return_value = {"wallet_id": 123}
    result = wallet.get_wallet_by_id(123)

    assert result["wallet_id"] == 123
    mock_wallet_db.get_wallet.assert_called_once_with(wallet_id=123)


# ---------------------------------------------------------------------
# TEST: get_balance_from_address
# ---------------------------------------------------------------------
@patch("bitcoin_wallet.wallet.requests.get")
def test_get_balance_from_address_success(mock_get, mock_wallet_deps):
    wallet, _, _ = mock_wallet_deps

    mock_response = MagicMock()
    mock_response.json.return_value = {"balance": 1000}
    mock_response.raise_for_status.return_value = None
    mock_get.return_value = mock_response

    result = wallet.get_balance_from_address("tb1qabc123")

    assert result == {"balance": 1000}
    mock_get.assert_called_once()
    assert "tb1qabc123" in mock_get.call_args[0][0]


@patch("bitcoin_wallet.wallet.requests.get")
def test_get_balance_from_address_handles_exception(mock_get, mock_wallet_deps):
    wallet, _, _ = mock_wallet_deps

    mock_get.side_effect = Exception("Network error")

    result = wallet.get_balance_from_address("tb1qabc123")

    assert result is None
