"""Based on "Decrypting password-based encrypted backup data for Huawei smartphones"
(https://www.researchgate.net/publication/330731285_Decrypting_password-based_encrypted_backup_data_for_Huawei_smartphones)

Adopted from https://github.com/RealityNet/kobackupdec
"""

import os
import sys
import pathlib
import binascii
import argparse
import xml.dom.minidom
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter


def decrypt(data, pwd_sha256, iv):
    iv_int = int.from_bytes(binascii.unhexlify(iv), byteorder="big")
    counter = Counter.new(
        128,
        initial_value=iv_int,
        little_endian=False,
    )
    decryptor = AES.new(pwd_sha256, mode=AES.MODE_CTR, counter=counter)
    return decryptor.decrypt(data)


def main(pwd, xml_path, src_folder, out_folder):
    pwd_sha256 = SHA256.new(pwd).digest()[:16]
    with xml_path.open("r", encoding="utf-8") as xml_file:
        xml_dom = xml.dom.minidom.parse(xml_file)

    for entry in xml_dom.getElementsByTagName("File"):
        path = entry.getElementsByTagName("Path")[0].firstChild.data
        iv = entry.getElementsByTagName("Iv")[0].firstChild.data
        path = path.replace("\\", "/")[1:]
        print(path, iv)
        full_path = src_folder.joinpath(f"{path}.enc")

        data = full_path.read_bytes()
        decrypted_data = decrypt(data, pwd_sha256, iv)

        tmp_folder = dst_folder.joinpath(os.path.split(path)[0])
        tmp_folder.mkdir(parents=True, exist_ok=True)
        decrypted_path = dst_folder.joinpath(path)
        decrypted_path.write_bytes(decrypted_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--password", help="User entered password", required=True)
    parser.add_argument(
        "--xml_path",
        help="Path to xml file with info to decrypt the files",
        required=True,
    )
    parser.add_argument(
        "--src_folder",
        help="Source root folder with the files to decrypt. Example: HUAWEI P30 lite_2021-03-31 21.54.12/picture/",
        required=True,
    )
    parser.add_argument(
        "--dst_folder",
        help="Folder where the decrypted files are going to be stored",
        required=True,
    )

    args = parser.parse_args()
    pwd_utf8 = args.password.encode("utf-8")
    xml_path = pathlib.Path(args.xml_path).absolute()
    src_folder = pathlib.Path(args.src_folder).absolute()
    dst_folder = pathlib.Path(args.dst_folder).absolute()

    if not xml_path.exists():
        sys.exit("xml_path doesn't exists")
    if not src_folder.is_dir():
        sys.exit("src_folder doesn't exists")

    dst_folder.mkdir(parents=True, exist_ok=True)
    main(pwd_utf8, xml_path, src_folder, dst_folder)
