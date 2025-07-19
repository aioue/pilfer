#!/usr/bin/env python3
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
import configparser
from pathlib import Path

# pip install ansible-vault (https://github.com/tomoh1r/ansible-vault)
from ansible_vault import Vault


temp_vault_file_list_path = "vaultedFileList.json"
list_of_vault_encrypted_files = []
temp_hidden_encrypted_copies_directory_path = '.vault'


def get_vault_password_file():
    """Get vault password file from ansible.cfg or fall back to default locations"""
    # First try to read from ansible.cfg
    try:
        config = configparser.ConfigParser()
        config.read('ansible.cfg')
        if 'defaults' in config and 'vault_password_file' in config['defaults']:
            vault_file = config['defaults']['vault_password_file']
            # Expand tilde for home directory
            vault_file = os.path.expanduser(vault_file)
            if os.path.exists(vault_file):
                return vault_file
    except Exception:
        pass
    
    # Fall back to common locations
    fallback_locations = [
        "../../vault_password_file",  # Original default
        "~/.ansible-vault/.vault-file",  # Common location
        ".vault_password",  # Local project file
        "vault_password_file"  # Simple local file
    ]
    
    for location in fallback_locations:
        expanded_location = os.path.expanduser(location)
        if os.path.exists(expanded_location):
            return expanded_location
    
    raise FileNotFoundError("Could not find vault password file. Please ensure it exists or specify with -p argument.")


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
            try:
                with open(filePath, 'rb') as open_file:
                    first_line = open_file.readline()

                    if first_line.startswith(b'$ANSIBLE_VAULT;'):
                        # print filePath
                        list_of_vault_encrypted_files.append(filePath)
            except (IOError, OSError, PermissionError):
                # Skip files we can't read
                continue

    # print vaultedFileList
    with open(temp_vault_file_list_path, 'w') as open_file:
        json.dump(list_of_vault_encrypted_files, open_file, indent=2)


def decrypt_vault_files(vault_password_file_path=None):
    # load the list of encrypted files
    with open(temp_vault_file_list_path, 'r') as vaultListFile:
        vaultedFileList = json.load(vaultListFile)

        # list the detected encrypted files
        # print json.dumps(vaultedFileList, indent=2)

    # determine vault password file
    if vault_password_file_path:
        vault_file = vault_password_file_path
    else:
        vault_file = get_vault_password_file()

    # load vault password into memory
    with open(vault_file, 'r') as vault_password_file:
        vaultPassword = vault_password_file.read().strip()

    # create a new Vault instance
    vault = Vault(vaultPassword)

    # iterate over the list of vaulted files
    for vaultedFilePath in vaultedFileList:
        try:
            # recursively build a mirror directory structure for this file
            mkdir_p(os.path.join(temp_hidden_encrypted_copies_directory_path + vaultedFilePath))

            # make a copy of the encrypted file
            shutil.copy2(vaultedFilePath, temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/encrypted')

            # decrypt the file
            with open(vaultedFilePath, 'r') as f:
                decryptedFileContents = vault.load_raw(f.read())

            # Convert bytes to string if necessary
            if isinstance(decryptedFileContents, bytes):
                decryptedFileContents = decryptedFileContents.decode('utf-8')

            # write a hash of the decrypted file to disk in the temporary directory
            file_hash = hashlib.sha256(decryptedFileContents.encode('utf-8')).hexdigest()
            with open(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/hash', 'w') as decryptedVaultFileHash:
                decryptedVaultFileHash.write(file_hash)

            # write the decrypted data to disk
            with open(vaultedFilePath, 'w') as decryptedVaultFile:
                decryptedVaultFile.write(decryptedFileContents)
                
        except Exception as e:
            print(f"Failed to decrypt {vaultedFilePath}: {e}")
            continue


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def recrypt_vault_files(vault_password_file_path=None):
    with open(temp_vault_file_list_path, 'r') as vaultListFile:
        vaultedFileList = json.load(vaultListFile)

    # determine vault password file
    if vault_password_file_path:
        vault_file = vault_password_file_path
    else:
        vault_file = get_vault_password_file()

    # load vault password into memory
    with open(vault_file, 'r') as vault_password_file:
        vaultPassword = vault_password_file.read().strip()

    # create a new Vault instance
    vault = Vault(vaultPassword)

    # iterate over the list of vaulted files
    for vaultedFilePath in vaultedFileList:
        try:
            # Load stored data
            with open(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/encrypted', 'r') as f:
                old_data = f.read()

            with open(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/hash', 'r') as f:
                old_hash = f.read().strip()

            # Load (potentially) new data from original path
            with open(vaultedFilePath, 'r') as f:
                new_data = f.read()
                new_hash = hashlib.sha256(new_data.encode('utf-8')).hexdigest()

            # Determine whether to re-encrypt
            if old_hash != new_hash:
                # File was modified, re-encrypt it
                new_data = vault.dump_raw(new_data)
            else:
                # File unchanged, restore original encrypted version
                new_data = old_data

            # Update file
            with open(vaultedFilePath, 'w') as f:
                f.write(new_data)

            # Clean vault
            try:
                os.remove(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/encrypted')
                os.remove(temp_hidden_encrypted_copies_directory_path + vaultedFilePath + '/hash')
                os.removedirs(temp_hidden_encrypted_copies_directory_path + vaultedFilePath)
            except Exception as e:
                print(f"Warning: Failed to clean temp files for {vaultedFilePath}: {e}")
        except Exception as e:
            print(f"Failed to process {vaultedFilePath}: {e}")
            continue
    
    try:
        os.removedirs(temp_hidden_encrypted_copies_directory_path)
    except Exception:
        pass

    try:
        os.remove(temp_vault_file_list_path)
    except Exception:
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
            decrypt_vault_files(args.vault_password_file)
        else:
            write_vaulted_file_list()
            decrypt_vault_files(args.vault_password_file)

    elif args.action == 'close':
        recrypt_vault_files(args.vault_password_file)
