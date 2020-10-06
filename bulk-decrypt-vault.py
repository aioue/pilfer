#!/usr/bin/python
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# heavily borrows from this excellent repo https://github.com/dellis23/ansible-toolkit

# bulk decrypt recrypt ansible vault files
# ./bulk-decrypt-vault.py [open|close]

import argparse
import errno
import hashlib
import json
import os
import shutil



# pip install ansible-vault (https://github.com/tomoh1r/ansible-vault)
from ansible_vault import Vault
# pip install pathlib(2?)
from pathlib import Path


# extend Vault to allow for raw
# https://stackoverflow.com/a/50859586/1053741
class MyVault(Vault):
    def load_raw(self, stream):
        return self.vault.decrypt(stream)

    def dump_raw(self, text, stream=None):
        encrypted = self.vault.encrypt(text)
        if stream:
            stream.write(encrypted)
        else:
            return encrypted


temp_vault_file_list_path = "vaultedFileList.json"
list_of_vault_encrypted_files = []
temp_hidden_encrypted_copies_directory_path = '.vault'
VAULT_PASSWORD_PATH = "../../vault_password_file"


# find all files that have the ansible vault header and write it to disk
def write_vaulted_file_list():
    walk_dir = os.path.abspath(os.getcwd())

    for dirpath, dirnames, filenames in os.walk(walk_dir):

        for name in filenames:
            # print name

            # disable filename filter since we might have encrypted everything
            # yamlExtensions = ('yml','yaml')
            # if name.endswith(yamlExtensions):
            #     print name

            # full path
            filePath = os.path.join(dirpath, name)
            # print filePath

            # find all files with the ansible vault header
            with open(filePath, 'rb') as open_file:
                first_line = open_file.readline()

                if first_line.startswith('$ANSIBLE_VAULT;'):
                    # print filePath
                    list_of_vault_encrypted_files.append(filePath)

    # print vaultedFileList
    with open(temp_vault_file_list_path, 'wb') as open_file:
        json.dump(list_of_vault_encrypted_files, open_file, indent=2)


def decrypt_vault_files():
    # load the list of encrypted files
    with open(temp_vault_file_list_path, 'rb') as vaultListFile:
        vaultedFileList = json.load(vaultListFile)

        # list the detected encrypted files
        # print json.dumps(vaultedFileList, indent=2)

    # load vault password into memory
    with open(VAULT_PASSWORD_PATH, 'r') as vault_password_file:
        vaultPassword = vault_password_file.read().strip()

    # create a new Vault instance with the
    vault = MyVault(vaultPassword)

    # iterate over the list of vaulted files
    for vaultedFilePath in vaultedFileList:
        # recursively build a mirror directory structure for this file
        mkdir_p(os.path.join(temp_hidden_encrypted_copies_directory_path + vaultedFilePath))

        # make a copy of the encrypted file
        shutil.copy2(vaultedFilePath, temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/encrypted')

        # decrypt the file
        decryptedFileContents = vault.load_raw(open(vaultedFilePath).read())

        # write a hash of the decrypted file to disk in the temporary directory
        with open(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/hash', 'wb') as decryptedVaultFileHash:
            decryptedVaultFileHash.write(hashlib.sha1(decryptedFileContents).hexdigest())

        # write the decrypted data to disk
        with open(vaultedFilePath, 'wb') as decryptedVaultFile:
            decryptedVaultFile.write(decryptedFileContents)


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def recrypt_vault_files():
    with open(temp_vault_file_list_path, 'rb') as vaultListFile:

        vaultedFileList = json.load(vaultListFile)

    # load vault password into memory
    with open(VAULT_PASSWORD_PATH, 'r') as vault_password_file:
        vaultPassword = vault_password_file.read().strip()

    # create a new Vault instance with the
    vault = MyVault(vaultPassword)

    # iterate over the list of vaulted files
    for vaultedFilePath in vaultedFileList:

        # Load stored data
        with open(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/encrypted', 'rb') as f:
            old_data = f.read()

        with open(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/hash', 'rb') as f:
            old_hash = f.read()

        # Load (potentially) new data from original path
        with open(vaultedFilePath, 'rb') as f:
            new_data = f.read()
            new_hash = hashlib.sha1(new_data).hexdigest()

        # Determine whether to re-encrypt
        if old_hash != new_hash:
            new_data = vault.dump_raw(new_data)
        else:
            new_data = old_data

        # Update file
        with open(vaultedFilePath, 'wb') as f:
            f.write(new_data)

        # Clean vault
        try:
            os.remove(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/encrypted')
            os.remove(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/hash')
            os.removedirs(temp_hidden_encrypted_copies_directory_path + vaultedFilePath)
        except Exception as e:
            print "FAIL"
            pass
    try:
        os.removedirs(temp_hidden_encrypted_copies_directory_path)
    except Exception as e:
        pass

    try:
        os.remove(temp_vault_file_list_path)
    except Exception as e:
        pass


if __name__ == '__main__':

    # Parse Args
    parser = argparse.ArgumentParser()
    parser.add_argument('action', help="open, close")
    parser.add_argument('-p', '--vault-password-file', type=str,
                        help="Path to vault password file")
    args = parser.parse_args()
    if args.action not in ['open', 'close']:
        raise RuntimeError(
            "command must be either 'open' or 'close'")

    # Open / Close Vault
    if args.action == 'open':

        # check for an existing encrypted file list
        # if one exists, decrypt the files
        # if it doesn't, make one
        if Path(temp_vault_file_list_path).is_file():
            # print "path exists, skipping file creation"
            decrypt_vault_files()
        else:
            write_vaulted_file_list()
            decrypt_vault_files()

    elif args.action == 'close':
        recrypt_vault_files()
