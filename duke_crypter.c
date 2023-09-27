#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

void handleErrors(void);

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *ciphertext, unsigned char *tag);

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr, "Syntax:\n");
    fprintf(stderr,
            " To encrypt: ./duke-crypter -e <input_file> <output_file>\n");
    fprintf(stderr,
            " To decrypt: ./duke-crypter -d <input_file> <output_file>\n");
    return 1;
  }

  char *operation = argv[1];
  char *input_file = argv[2];
  char *output_file = argv[3];

  if (strcmp(operation, "-e") != 0 && strcmp(operation, "-d") != 0) {
    fprintf(stderr, "Invalid operation: %s\n", operation);
    return 1;
  }

  // read stdin to keyChar, hash with SHA256, store in key

  /* A 128 bit IV */
  // unsigned char *iv = (unsigned char *)"0123456789012345";
  // size_t iv_len = 16;

  FILE *inputFile = fopen(input_file, "rb");
  if (!inputFile) {
    fprintf(stderr, "Error: Unable to open input file.\n");
    return 1;
  }

  fseek(inputFile, 0, SEEK_END);
  long fileSize = ftell(inputFile);
  fseek(inputFile, 0, SEEK_SET);

  // encryption
  if (strcmp(operation, "-e") == 0) {
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    size_t iv_len = 16;

    char keyChar[32];
    scanf("%32s", keyChar);
    unsigned char hash[32];
    SHA256((const unsigned char *)keyChar, strlen(keyChar), hash);
    unsigned char *key = hash;

    unsigned char *plaintext = (unsigned char *)malloc(fileSize);
    fread(plaintext, 1, fileSize, inputFile);

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[fileSize + 16];

    /* Buffer for the tag */
    unsigned char tag[16];

    int ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = gcm_encrypt(plaintext, fileSize, NULL, 0, key, iv, iv_len,
                                 ciphertext, tag);

    // write to output file
    FILE *outputFile = fopen(output_file, "wb");

    fwrite(tag, 1, 16, outputFile);
    fwrite(iv, 1, 16, outputFile);
    fwrite(ciphertext, 1, ciphertext_len, outputFile);
    fclose(outputFile);
  }

  // decryption
  else {
    char keyChar[32];
    scanf("%32s", keyChar);
    unsigned char hash[32];
    SHA256((const unsigned char *)keyChar, strlen(keyChar), hash);
    unsigned char *key = hash;

    unsigned char decryptedtext[fileSize];
    char fileData[fileSize];
    unsigned char tag[16];
    unsigned char iv[16];
    int iv_len = 16;
    fread(fileData, 1, fileSize, inputFile);

    // Distribute the first 16 bytes to the tag, the next 16 to the iv
    memcpy(tag, fileData, 16);
    memcpy(iv, fileData + 16, 16);

    // Calculate the length of the ciphertext
    long ciphertext_len = fileSize - 32;

    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len);
    memcpy(ciphertext, fileData + 32, ciphertext_len);

    long decryptedtext_len;

    /* Decrypt the ciphertext */
    decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len, NULL, 0, tag,
                                    key, iv, iv_len, decryptedtext);

    if (decryptedtext_len < 0) {
      return 1;
    }

    FILE *outputFile = fopen(output_file, "wb");
    fwrite(decryptedtext, 1, decryptedtext_len, outputFile);
    fclose(outputFile);
  }

  fclose(inputFile);

  return 0;
}

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *ciphertext, unsigned char *tag) {
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    handleErrors();

  /*
   * Set IV length if default 12 bytes (96 bits) is not appropriate
   */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    handleErrors();

  /* Initialise key and IV */
  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
   * Finalise the encryption. Normally ciphertext bytes may be written at
   * this stage, but this does not occur in GCM mode
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Get the tag */
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    handleErrors();

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. */
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    handleErrors();

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    handleErrors();

  /* Initialise key and IV */
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

  /*
   * Provide any AAD data. This can be called zero or more times as
   * required
   */
  if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) handleErrors();

  /*
   * Finalise the decryption. A positive return value indicates success,
   * anything else is a failure - the plaintext is not trustworthy.
   */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0) {
    /* Success */
    plaintext_len += len;
    return plaintext_len;
  } else {
    /* Verify failed */
    return -1;
  }
}
