#include <gpgme.h> // all gpg functions
#include <stdio.h> // print etc.
#include <errno.h> // errors
#include <locale.h> // local environment
#include <stdlib.h>
#include <string.h>

#define MAXLEN 4096
#define KEYRING_DIR "/home/petru/.gnupg/"
#define TEXT "Encrypting and decrypting 101"

int main(int argc, char **argv) {

  gpgme_error_t error;
  gpgme_ctx_t context;
  gpgme_engine_info_t info;
  gpgme_user_id_t user;
  gpgme_data_t plain_text;
  gpgme_data_t encrypted_text;
  gpgme_encrypt_result_t encryption_result;
  gpgme_key_t recipients[2] = {NULL, NULL};
  char* buffer_encryption = NULL;
  char* buffer_decryption = NULL;
  ssize_t encrypted_text_size;
  ssize_t plain_text_size;
  /* Initialize the locale environment.  */
  setlocale (LC_ALL, "");
  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  #ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
  #endif

  error = gpgme_new(&context);
  if (error)
  {
    fprintf (stderr, "%s: creating GpgME context failed: %s: %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
    exit (1);
  }

  gpgme_set_armor(context, 1); //view in ASCII
  /* Check OpenPGP */
  error = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
  if (error)
  {
    fprintf (stderr, "%s: GPGME_PROTOCOL_OpenPGP failed: %s: %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
    exit (1);
  }
  error = gpgme_get_engine_info (&info);
  if (error)
  {
    fprintf (stderr, "%s: get_engine_info failed %s: %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
    exit (1);
  }

  while (info && info->protocol != gpgme_get_protocol (context)) {
    info = info->next;
  }

  /* Initialize the context */
  error = gpgme_ctx_set_engine_info (context, GPGME_PROTOCOL_OpenPGP, NULL,
             KEYRING_DIR);
  if (error)
  {
    fprintf (stderr, "%s: keyring_directory failed: %s: %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
    exit (1);
  }

  error = gpgme_op_keylist_start(context, "Petru", 1);
  if(error)
  {
    fprintf (stderr, "%s: keylist_start failed: %s: %s\n",
           argv[0], gpgme_strsource (error), gpgme_strerror (error));
    exit (1);

  }
  error = gpgme_op_keylist_next(context, &recipients[0]);
  if(error)
  {
    fprintf (stderr, "%s: keylist_next failed: %s: %s\n",
           argv[0], gpgme_strsource (error), gpgme_strerror (error));
    exit (1);

  }
  error = gpgme_op_keylist_end(context);
  if(error)
  {
    fprintf (stderr, "%s: keylist_end failed: %s\
             : %s\n",
           argv[0], gpgme_strsource (error), gpgme_strerror (error));
    exit (1);
  }
  if(recipients[0] == NULL)
  {
    fprintf (stderr, "there is no such an user \n");
  }

    user = recipients[0]->uids;
    printf("Encrypting for %s <%s>\n", user->name, user->email);


    /* Preparing the data buffer */
    error = gpgme_data_new_from_mem(&plain_text, TEXT, strlen(TEXT), 1);

    //    error = gpgme_data_new_from_mem(&encrypted_text2, TEXT, 10, 1);
    if(error)
    {
      fprintf (stderr, "%s: data_from_mem failed for encryption: \
      %s : %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
      exit (1);
    }
    error = gpgme_data_new(&encrypted_text);
    if(error)
    {
      fprintf (stderr, "%s: gpgme_data_new failed for encryption%s : %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
      exit (1);
    }

    /* Encrypt */
    error = gpgme_op_encrypt(context, recipients, GPGME_ENCRYPT_ALWAYS_TRUST,
                             plain_text, encrypted_text);
    if(error)
    {
      fprintf (stderr, "%s: op_encrypt failed %s : %s\n",
               argv[0], gpgme_strsource (error), gpgme_strerror (error));
      exit (1);
    }

    encryption_result = gpgme_op_encrypt_result(context);
    if (encryption_result->invalid_recipients)
    {
        fprintf (stderr, "Invalid recipient found: %s\n",
  	       encryption_result->invalid_recipients->fpr);
        exit (1);
    }

    encrypted_text_size = gpgme_data_seek (encrypted_text, 0, SEEK_END);
    if (encrypted_text_size == -1)
    {
      fprintf (stderr, "Error in data seek at encryption");
      exit (1);
    }
    gpgme_data_seek (encrypted_text, 0, SEEK_SET);
    buffer_encryption = (char *) malloc(encrypted_text_size + 100);

    encrypted_text_size = gpgme_data_read(encrypted_text, buffer_encryption,
                                          MAXLEN);

    if (encrypted_text_size == -1)
    {
      fprintf (stderr, "Error in data read at encryption");
      exit (1);
    }
    buffer_encryption[encrypted_text_size] = '\0';
    printf("Encrypted text (%i bytes):\n", (int)encrypted_text_size);
    printf("%s\n", buffer_encryption);

    gpgme_data_release (plain_text);
    gpgme_data_release (encrypted_text);
    /* Decrypt */


  error = gpgme_data_new_from_mem(&encrypted_text, buffer_encryption,
                                  encrypted_text_size, 1);

    if(error)
    {
      fprintf (stderr, "%s: data_from_mem failed for decryption: \
      %s : %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
      exit (1);
    }

    error = gpgme_data_new(&plain_text);
    if(error)
    {
      fprintf (stderr, "%s: gpgme_data_new failed for decryption%s : %s\n",
             argv[0], gpgme_strsource (error), gpgme_strerror (error));
      exit (1);
    }

    error = gpgme_op_decrypt (context, encrypted_text, plain_text);
    if(error)
    {
      fprintf (stderr, "%s: op_decrypt failed %s : %s\n",
               argv[0], gpgme_strsource (error), gpgme_strerror (error));
      exit (1);
    }

    plain_text_size = gpgme_data_seek (plain_text, 0, SEEK_END);
    if (plain_text_size == -1)
    {
      fprintf (stderr, "Error in data seek at decryption ");
      exit (1);
    }
    gpgme_data_seek (plain_text, 0, SEEK_SET);
    buffer_decryption = (char *) malloc(plain_text_size + 100);

    plain_text_size = gpgme_data_read(plain_text, buffer_decryption,
                                          MAXLEN);
    if (plain_text_size == -1)
    {
      fprintf (stderr, "Error in data read at decryption");
      exit (1);
    }
    printf("Decrypted text (%i bytes):\n", (int)plain_text_size);
    printf("%s\n", buffer_decryption);
    
    return 0;
}
