/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT_TCP 55555
#define PORT_UDP 55554
#define PORT_SSL "55559"

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

// Declaring these as global variables to clean them in case of a break operation.
int sock_fd_udp, net_fd, sock_fd;
BIO * bio, *bbio, *acpt, *out;
SSL_METHOD *meth;
SSL_CTX *ctx;
SSL *ssl;
X509 *client_cert;
SSL_SESSION *session;

  /* A 256 bit key */
  unsigned char *key;

  /* A 128 bit IV */
  unsigned char *iv;



// Handles ctrl+B break functionality.
void sigint_handler(int signum) {
    printf("\nCtrl+C signal received. Exiting...\n");
    close(sock_fd_udp);
    close(net_fd);
    BIO_free_all(bio);
    BIO_free(out);
    SSL_CTX_free(ctx);
    
    // Additional cleanup or exit actions can be added here
    exit(signum);
}


// Encrypt AES
int encrypt_aes(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) 
{
  // Variables
  EVP_CIPHER_CTX *aes_ctx;
  int len;
  int ciphertext_len;

  if (!(aes_ctx = EVP_CIPHER_CTX_new())) {
      perror("EVP_CIPHER_CTX_new init Context error");
      exit(1);
  }

  if (!(EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, key, iv))) {
      perror("EVP_EncryptInit_ex Cipher error");
      exit(1);
  }

  if (!(EVP_EncryptUpdate(aes_ctx, ciphertext, &len, plaintext, plaintext_len))) {
      perror("EVP_EncryptUpdate AES");
      exit(1);
  }
  ciphertext_len = len;

  if (!(EVP_EncryptFinal_ex(aes_ctx, ciphertext + len, &len))) {
      perror("EVP_EncryptFinal_ex AES");
      exit(1);
  }
  ciphertext_len += len;

  //Clean Up
  EVP_CIPHER_CTX_free(aes_ctx);

  return ciphertext_len;
}

int decrypt_aes(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) 
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	/* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) 
  {
    perror("EVP_CIPHER_CTX_new error");
    exit(1);
  }

  
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) 
  {
      perror("EVP_DecryptInit_ex error");
      exit(1);
  }

  
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
  {
    perror("EVP_DecryptUpdate error");
    exit(1);
  }

  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
  * this stage.
  */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
  {
    perror("EVP_DecryptFinal_ex error");
    exit(1);
  }

  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;

}

// Function to generate HMAC using SHA-256 hash algorithm from Open SSL libraries.
unsigned char* get_hmac(unsigned char *key, unsigned char *buffer) {
    unsigned char* hmac;
    hmac = HMAC(EVP_sha256(), key, strlen((const char *)key), buffer, strlen((const char *)buffer), NULL, NULL);
    return hmac;
}

// Compare the previous generated HMAC.
int compare_hmac(unsigned char *key, unsigned char *buffer, unsigned char *hmac) {
    unsigned char* new_hmac;
    new_hmac = get_hmac(key, buffer);
    int i;

    // Iterate through each byte of the HMAC
    for(i = 0; i < 32; i++) {
        // If any byte of the given and new HMACs does not match, return 0
        if (hmac[i] != new_hmac[i]){
            return 0;
        }
    }

    return 1;
}


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  fprintf(stderr, "ctrl + b breaks the connect and frees the memory objects.\n");
  exit(1);
}

void InitializeSSL(){

  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  OPENSSL_config(NULL);
}

/**************************************************************************
 * HandleAndVerifyServerSSL: Initiates and verifies a server SSL connection.
 *    This will also sets/updates the Session key in the global variables.
 *    Referenced from: https://web.archive.org/web/20140822070735/http://www.openssl.org/docs/ssl/ssl.html
 **************************************************************************/
void HandleAndVerifyClientSSL(char *client_ip){
  InitializeSSL();
    do_debug("Attempting to to connect to the server... ");

  ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    if (SSL_CTX_use_certificate_file(ctx, "./certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/client.key", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    if (SSL_CTX_check_private_key(ctx) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    if (SSL_CTX_load_verify_locations(ctx, "./certs/ca.crt", NULL) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    bio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(bio, &ssl);

    if (!ssl) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }

    /* Don't want any retries */
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* set connection parameters */
    BIO_set_conn_hostname(bio, client_ip);
    BIO_set_conn_port(bio, PORT_SSL);

    /* create a buffer to print to the screen */
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* establish a connection to the server */
    do_debug("Attempting to to connect to the server... ");
    if (BIO_do_connect(bio) <= 0) {
      do_debug("Error connecting to server\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      BIO_free(out);
      SSL_CTX_free(ctx);
      exit(1);
    }
    do_debug("done.\n");

    /* initiate the handshake with the server */
    do_debug("Initiating SSL handshake with the server... ");
    if (BIO_do_handshake(bio) <= 0) {
      do_debug("Error establishing SSL connection\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      BIO_free(out);
      SSL_CTX_free(ctx);
      exit(1);
    }
    do_debug("done.\n");

    /* We retrieve the master key from the session */
    session = SSL_get_session(ssl);
    //print_hex(session->master_key, session->master_key_length);
    // do_debug("Get key from session:\n");
    memcpy(key, (session->master_key), 32);
    //print_hex(key, 32);
    // do_debug("Get IV from session:\n");
    memcpy(iv, &(session->master_key[32]), 16);
    //print_hex(iv, 16);
    return;
}

/**************************************************************************
 * HandleAndVerifyServerSSL: Initiates and verifies a client SSL connection.
 *    This will also sets/updates the Session key in the global variables.*
 **************************************************************************/
void HandleAndVerifyServerSSL(char *client_ip){
    do_debug("Init SSL \n");
  InitializeSSL();
    do_debug("Init SSL success. \n");
  ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("ctx success. \n");
    if (SSL_CTX_use_certificate_file(ctx, "./certs/server.crt", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("loaded server cert. \n");
    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/server.key", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("loaded server private key. \n");
    if (SSL_CTX_check_private_key(ctx) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("Server private key valid. \n");
    if (SSL_CTX_load_verify_locations(ctx, "./certs/ca.crt", NULL) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("loaded CA cert. \n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    
    do_debug("Set to peer verify on connection. \n");

    /* New SSL BIO setup as server */
    bio = BIO_new_ssl(ctx, 0);

    BIO_get_ssl(bio, &ssl);

    if (!ssl) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }

    /* Create the buffering BIO */
    bbio = BIO_new(BIO_f_buffer());

    /* Add to chain */
    bio = BIO_push(bbio, bio);

    acpt = BIO_new_accept(PORT_SSL);
    BIO_set_accept_bios(acpt, bio);

    /* Setup accept BIO */
    do_debug("Setting up the accept BIO... ");
    if (BIO_do_accept(acpt) <= 0) {
      do_debug("Error setting up accept BIO\n");
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("done.\n");

    /* Now wait for incoming connection */
    do_debug("Setting up the incoming connection... ");
    if (BIO_do_accept(acpt) <= 0) {
      do_debug("Error in connection\n");
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("done.\n");

    /* We only want one connection so remove and free
     * accept BIO
     */

    bio = BIO_pop(acpt);

    BIO_free_all(acpt);

    /* wait for ssl handshake from the client */
    do_debug("Waiting for SSL handshake... ");
    if (BIO_do_handshake(bio) <= 0) {
      do_debug("Error in SSL handshake\n");
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    do_debug("done.\n");
    srand((unsigned)time(NULL));
    BIO_flush(bio);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    sleep(1); // sometimes the ssl pointer is not ready?
    BIO_get_ssl(bio, &ssl);
    session = SSL_get_session(ssl);


    memcpy(key, (session->master_key), 32);
    //print_hex(key, 32);
    memcpy(iv, &(session->master_key[32]), 16);
    //print_hex(iv, 16);
    return;
}

int main(int argc, char *argv[]) {
  
  if (signal(SIGINT, sigint_handler) == SIG_ERR) {
      perror("Error registering signal handler");
      return EXIT_FAILURE;
    }
    else{
      BIO_free_all(bio);
      BIO_free(out);
      SSL_CTX_free(ctx);
      close(sock_fd_udp);
      close(net_fd);
    }

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE], buffer_encrypted[BUFSIZE], buffer_decrypted[BUFSIZE];
  struct sockaddr_in local, remote;
  char client_ip[16] = "";
  unsigned short int port = PORT_UDP;
  int optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  

  progname = argv[0];
  
  key = (unsigned char*)malloc(32);
  iv = (unsigned char*)malloc(16);

  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(client_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*client_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  // TCP is used to test the connection. We don't listen on this.
  if(cliserv==CLIENT){
    HandleAndVerifyClientSSL(client_ip);
    /* Client, try to connect to server */


    /* assign the destination address */
    
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(client_ip);
    remote.sin_port = htons(PORT_TCP);

    sleep(5); // sometimes the ssl pointer is not ready?
    /* connection request */
    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
      perror("connect()");
      exit(1);
    }

    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
  } else {
    HandleAndVerifyServerSSL(client_ip);

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(PORT_TCP);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    
    do_debug("Server: Waiting for TCP connections");
    if (listen(sock_fd, 5) < 0){
      perror("listen()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    remote.sin_port = htons(PORT_TCP);
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
      perror("accept()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }




  
  // Let's take advantage of TCP handshake. In UDP we don't care who is client and who is server. 
  // Listen(recvfrom) on port 55554 for data and send to the other device's address we got from TCP accept, on 55554.
  // Let's create a socket file descriptor, one for the local address (listening) and other for other party's address (sending) 

  struct sockaddr_in current_device, other_device;
  if ((sock_fd_udp = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
  }

  
  if(setsockopt(sock_fd_udp, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt()");
    exit(1);
  }

  memset(&current_device, 0, sizeof(current_device));
    current_device.sin_family = AF_INET;
    current_device.sin_addr.s_addr = htonl(INADDR_ANY);
    current_device.sin_port = htons(PORT_UDP);

  if (bind(sock_fd_udp, (struct sockaddr *)&current_device, sizeof(current_device)) == -1) {
      perror("bind");
      close(sock_fd_udp);
      exit(EXIT_FAILURE);
  }

  memset(&other_device, 0, sizeof(other_device));
    other_device.sin_family = AF_INET;
    other_device.sin_addr.s_addr = remote.sin_addr.s_addr;
    other_device.sin_port = htons(PORT_UDP);

  net_fd = sock_fd_udp;

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);

      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
      
      nread = encrypt_aes(buffer, nread, key, iv, buffer_encrypted);
      unsigned char* t = get_hmac(key, buffer_encrypted);
      memcpy(buffer_encrypted + nread, t, 32);
      do_debug("Packet is end to end encrypted and hashed!");

      nwrite = sendto(net_fd, buffer_encrypted, nread + 32, 0, (struct sockaddr *)&other_device, sizeof(other_device));

      if (nwrite == -1) {
          perror("Sending packet data failed");
          close(net_fd);
          exit(EXIT_FAILURE);
      }
      
      // increment the counter after copy.
      tap2net++;

      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      int remote_len = sizeof(other_device);
      nread = recvfrom(net_fd, buffer, BUFSIZE, 0, (struct sockaddr *)&other_device, &remote_len);
      if (nread == -1) {
          perror("UDP receive failed");
          close(net_fd);
          exit(EXIT_FAILURE);
      }
      
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
      
      char temp[BUFSIZE];
      memcpy(temp, buffer, nread - 32);
      if (compare_hmac(key, temp, buffer + nread)) {
        perror("Wrong");
        exit(1);
      }
      do_debug("Hash validated.\n");
      
      nread = decrypt_aes(temp, nread - 32, key, iv, buffer_decrypted);


      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer_decrypted, nread);
      net2tap++;
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  close(sock_fd_udp);
  close(net_fd);

  return(0);
}
