# 560crypter

reverse engineering: https://github.com/weidai11/cryptopp
openssl aes: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

Syntax:

 To encrypt: ./duke-crypter -e <input_file> <output_file>
 
 To decrypt: ./duke-crypter -d <input_file> <output_file>

To verify: python3 cryptotest.pyc /path/to/duke-crypter

To bypass the validation: decrypt the cheat_instruction.enc. key is uni_name + course_name, no capital letter.
