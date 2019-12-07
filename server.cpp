#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <openssl/sha.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#define PORT 50505
#define BUFFER_S 1024
#define HASH_S 20
#define NUM_IDX 4
#define DAT_IDX 8
using namespace std;
static int sd;

static void closeServerHandler() {
  printf("\nClosing server ...\n");
  close(sd);
  exit(EXIT_SUCCESS);
}
//!!!!!!LIMITATIONS!!!!!!!
// can send up to 4Gb, name is up to 1000 char long

// function declaration
// void send_ACK(char *buffer, int b_size, int s_size, int sd,
// struct sockaddr *server);

struct File_informations{
  bool rcv_name;
  bool rcv_size;
  bool rcv_hash;
  char name[1000];
  char hash[20];
  int size;
};

void send_ACK(int sd, char *buffer_tx, 
              struct sockaddr_in *client, socklen_t client_len);
// void send_resend(char *buffer, int b_size, socklen_t server_len, int sd,
// struct sockaddr *server);
void send_resend(int sd, char *buffer_tx, 
                 struct sockaddr_in *client, socklen_t client_len);
FILE *open_file(int sd, char *buffer_rx, char *buffer_tx,
                struct sockaddr_in *client, socklen_t client_len);
int get_file_size(int sd, char *buffer_rx, char *buffer_tx,
                  struct sockaddr_in *client, socklen_t client_len);
int *compute_crc(char *buffer, unsigned long crc, int buffer_len);
int get_hash(int sd, char *buffer_rx, char *buffer_tx,
             struct sockaddr_in *client, socklen_t client_len, char *hash);
bool check_crc(char *buffer_rx, int ret, 
               int data_start);

int main(void) {
  // variables
  struct sockaddr_in server, client;
  socklen_t client_len, server_len;
  int ret, rec_packet_num, last_packet_num;
  char buffer_tx[BUFFER_S];
  char buffer_rx[BUFFER_S];
  FILE *fd;
  char c;
  char size_msg[] = "SIZE=";
  char ACK[] = "ACK";
  bool trans_end = false, retransmit = false;
  char num_packet[4];

  // setting up the socket
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(PORT);
  sd = socket(AF_INET, SOCK_DGRAM, 0);
  bind(sd, (struct sockaddr *)&server, sizeof(server));

  // vubec nevim
  // signal(int __sig, __sighandler_t __handler)
  signal(SIGINT, (__sighandler_t)closeServerHandler);

  client_len = sizeof(client);
  server_len = sizeof(server);
  // main loop todo: another type of message, that exits the loop AKA msg_type
  // EXIT
  while (true) {
    printf("Čekám na packet od klienta ...\n");
    // parse msg with name and size todo: add crc to client and server
    fd = open_file(sd, buffer_rx, buffer_tx, &client, client_len);
    cout << "file is open" << endl;
    int transf = get_file_size(sd, buffer_rx, buffer_tx, &client, client_len);
    int file_length = transf;

    char hash_rcv[20];
    int hash_ret =
        get_hash(sd, buffer_rx, buffer_tx, &client, client_len, hash_rcv);

    cout << "RECEIVED HASH\n";
    for (int i = 0; i < 20; i++) {
      cout << (int)hash_rcv[i] << ":";
    }
    cout << endl;

    ////////////////////////////////////////////////////// HASH

    //  transf je delka toho srace co prijimam
    unsigned char *file_hash;
    char hash_buff[20];
    file_hash = (unsigned char *)malloc(transf);
    cout << "delka souboru" << transf << endl;
    //////////////////////////////////////////////////////

    trans_end = false;
    last_packet_num = 0;
    // have name and size, now get data
    int file_position = 0;
    while (!trans_end) {
      bool CRCerror = false;

      ret = recvfrom(sd, &buffer_rx, sizeof(buffer_rx), 0,
                     (struct sockaddr *)&client, &client_len);
      //  prijate CRC

      cout << endl;
      for (int i = NUM_IDX; i < NUM_IDX + 4; i++) {
        num_packet[i - NUM_IDX] = buffer_rx[i];
      }

      CRCerror = check_crc(buffer_rx, ret,  8);

      if (CRCerror) {

        // number of packet recieved, decide what to do now (ack, or error)
        rec_packet_num = atoi(num_packet);
        if (last_packet_num < rec_packet_num) {
          cout << "Packekt number error, server exiting" << endl;
          return -1;
        } else if (last_packet_num > rec_packet_num) {
          // send another ack message

        } else {
          // TODO tohle je jen dobug vole pak to odkomentuj
          // return 0;
          cout << "sending ACK" << endl;
          send_ACK(sd, buffer_tx, &client, client_len);
          for (int i = DAT_IDX; i < BUFFER_S; i++) {
            c = buffer_rx[i];
            putc(c, fd);

            file_hash[file_position] = c;
            file_position++;
            // TODO some edit
            transf--;
            if (transf == 0) {
              cout << "transmision end" << endl;
              ////////////////////////////////////////////////////// TODO toto
              /// by se nechalo dat asi cele do funkce

              SHA1(file_hash, file_length, (unsigned char *)hash_buff);
              // for (int i = 0; i < 20; i++) {
              // cout << (int)hash_buff[i] << ":";
              //}
              int hash_match = 1;

              for (int i = 1; i < 20; i++) {
                // printf("Obdrzeny je %d vypocitany je %d\n",
                // (int)hash_buff[i], (int)hash_rcv[i]);
                if ((char)hash_buff[i] != hash_rcv[i]) {
                  cout << "HASH FAILED- received file incorrectly" << hash_match
                       << endl;
                }
              }

             free(file_hash);

              ////////////////////////////////////////////////////// HASH

              trans_end = true;
              break;
            }
          }
        }
        last_packet_num++;

      } // tady konci if CRCerroru.. kdyz je error tak vsechny ty fancy veci
        // preskocim
    }
    // close current file, everithing is done
    // todo hash verification
    fclose(fd);
  }
  return 0;
}

void send_ACK(int sd, char *buffer_tx, 
              struct sockaddr_in *client, socklen_t client_len) {
  char ACK_msg[] = "ACK";
  memset(buffer_tx, 0, BUFFER_S);
  strcpy(buffer_tx, ACK_msg);
  int ret = sendto(sd, buffer_tx, 4, MSG_DONTWAIT,
                   (struct sockaddr *)client, client_len);
}

// kdyz nesedi CRCko tak poslu tuhle postizenou zpravu
void send_resend(int sd, char *buffer_tx, 
                 struct sockaddr_in *client, socklen_t client_len) {
  char resend_msg[] = "RESEND";
  memset(buffer_tx, 0, BUFFER_S);
  strcpy(buffer_tx, resend_msg);
  int ret = sendto(sd, buffer_tx, 7, MSG_DONTWAIT,
                   (struct sockaddr *)client, client_len);
}

int parse_msg(char *buffer_rx, int sd, char *buffer_tx, struct sockaddr_in *client, socklen_t client_len){
  //TODO check if you have all messages need aka name hash, some kind of timeout if i am recieving dat aleready
  char name_msg[] = "NAME=";
  char hash_msg[] = "HASH=";
  char size_msg[] = "SIZE=";
  char msg_type[6];
  int ret;
  int timeout;
  timeout = 0;
      ret = recvfrom(sd, buffer_rx, BUFFER_S, 0, (struct sockaddr *)client,
                     &client_len);
  bool CRC_error = check_crc(buffer_rx, ret, 4);
  while(!CRC_error){
      send_resend(sd, buffer_tx, client, client_len);
      ret = recvfrom(sd, buffer_rx, BUFFER_S, 0, (struct sockaddr *)client,
                     &client_len);
      CRC_error = check_crc(buffer_rx, ret , 4);
      timeout++;
      if(timeout > 100){
        cout << "Fatal error, CRC failed too many times" <<endl;
      }
  }
  send_ACK(sd, buffer_tx, client, client_len);
  for(int i = 4; i < 9; i++){
    msg_type[i-4] = buffer_rx[i];
  }
//TODO tady jsi skoncil voe, mas zjistit o jakou zpravu se jedna a podle toho ji poslat do fce
  return 0;
}
//// TODO CRCcko je tu implementovane.. jeho vysledek je v CRCerroru- nejak
/// zpracovat ten vysledek (poslat ACK nebo neco nevim)
//char *parse_name(char *buffer_rx, int size){
  //char crc_data[4];
  //char name_data[size - 9];

  //for(int i = 0; i < 4; i++){
    //crc_data[i] = buffer_rx[i];
  //}
//}
FILE *open_file(int sd, char *buffer_rx, char *buffer_tx,
                struct sockaddr_in *client, socklen_t client_len) {
  char name_msg[] = "NAME=";
  char path[] = "out/";
  char name[1000];
  int ret = recvfrom(sd, buffer_rx, BUFFER_S, 0, (struct sockaddr *)client,
                     &client_len);

  bool CRCerror = check_crc(buffer_rx, ret, 4);
  while (!CRCerror) {
    // send_resend(char *buffer, int b_size, int s_size, int sd,
    // struct sockaddr *server) send_resend(buffer_tx, ) int ret =
    recvfrom(sd, buffer_rx, BUFFER_S, 0, (struct sockaddr *)client,
             &client_len);
  }

  int name_len = strlen(buffer_rx);

  char check_name[6];
  for (int i = 0; i < 5; i++) {
    check_name[i] = buffer_rx[i + 4];
  }
  check_name[5] = '\0';
  int is_same = strcmp(check_name, name_msg);
  if (is_same != 0) {
    cout << "not NAME" << endl;
    return NULL;
  }
  memset(name, 0, 1000);
  strcpy(name, path);
  for (int i = 0; i < name_len - 5; i++) {
    name[strlen(path) + i] = buffer_rx[5 + i];
  }
  name[name_len + 5] = 0;
  cout << name << endl;
  FILE *fd = fopen(name, "w");
  return fd;
}

///
/// Jsou tri rano a napadaji me zajimave veci
///  napr u open_file u crcka zjistuju velikost bufferu z ktereho delam crcko
///  zjistuju to pomoci strlen, ktery hleda takovej ten stringovskej znak na
///  konci zejo CO KDYBY NAHOOODOU crcko zrovna vyslo tak, ze to bude cislo
///  odpovidajici tomu stringovskemu konci
/// hmmmmmmmmmm zamyslet see

//// TODO CRCcko je tu implementovane.. jeho vysledek je v CRCerroru- nejak
/// zpracovat ten vysledek (poslat ACK nebo neco nevim)
int get_file_size(int sd, char *buffer_rx, char *buffer_tx,
                  struct sockaddr_in *client, socklen_t client_len) {
  char size_msg[] = "SIZE=";
  char c_size[100];
  int ret = recvfrom(sd, buffer_rx, BUFFER_S, 0, (struct sockaddr *)client,
                     &client_len);

  for (int i = 0; i < 1024; i++) {
    cout << buffer_rx[i] << ":";
  }

  //// TODO POZOR POZOR SIZE_LEN JE NAHARDCODENE, funguje jen pro test.txt..
  /// OPRAVIT ASAP
  int size_len = sizeof(buffer_rx) + 5;
  bool CRCerror = check_crc(buffer_rx, size_len, 4);

  cout << "this is size" << size_len;

  char check_size[6];
  for (int i = 0; i < 5; i++) {
    check_size[i] = buffer_rx[i + 4];
  }
  check_size[5] = '\0';
  int is_same_num = strcmp(check_size, size_msg);
  if (is_same_num != 0) {
    cout << "not SIZE" << endl;
    return -1;
  }
  for (int i = 9; i < size_len; i++) {
    c_size[i - 9] = buffer_rx[i];
  }
  int msg_length = atoi(c_size);
  int transf = msg_length;
  cout << "function return size of file: " << transf << endl;
  return transf;
}

//// TODO CRCcko je tu implementovane.. jeho vysledek je v CRCerroru- nejak
/// zpracovat ten vysledek (poslat ACK nebo neco nevim)
int get_hash(int sd, char *buffer_rx, char *buffer_tx,
             struct sockaddr_in *client, socklen_t client_len, char *hash) {
  // returns 0 if everithing is ok or -x in case of some problem
  char hash_msg[] = "HASH=";
  char crc_data[4];
  char verify_hash[6];
  int ret = recvfrom(sd, buffer_rx, BUFFER_S, 0, (struct sockaddr *)client,
                     &client_len);

  bool CRCerror = check_crc(buffer_rx, 29, 4);

  if (ret != 29) {
    cout << "Hash msg length does not match" << endl;
    return -100;
  }
  // load crc

  for (int i = 0; i < 4; i++) {
    crc_data[i] = buffer_rx[i];
  }
  for (int i = 4; i < 9; i++) {
    verify_hash[i - 4] = buffer_rx[i];
  }
  for (int i = 9; i < 9 + HASH_S; i++) {
    hash[i - 9] = buffer_rx[i];
  }
  if (strcmp(hash_msg, verify_hash) != 0) {
    cout << "Not HASH=" << endl;
    return -1;
  }

  // TODO check for crc, if it does not match return -1 and ask for resend
  return 0;
}

int *compute_crc(char *buffer, unsigned long crc, int buffer_len) {
  unsigned char data[buffer_len];
  for (int i = 0; i < buffer_len; i++) {
    data[i] = buffer[i];
  }

  crc = crc32(crc, (const unsigned char *)data, buffer_len);
  string r;
  for (int i = 0; i < 32; i++) {
    r = (crc % 2 == 0 ? "0" : "1") + r;
    crc /= 2;
  }

  static int crc_4[4];
  int i = 0;
  for (i = 0; i < 4; i++) {
    // v rku je binarni string crcka (32 bitu), prevadim to na 4 8 bitove
    // integery, -48 protoze 1 je ascii 49
    crc_4[i] = 128 * ((int)r[i * 8] - 48) + 64 * ((int)r[i * 8 + 1] - 48) +
               32 * ((int)r[i * 8 + 2] - 48) + 16 * ((int)r[i * 8 + 3] - 48) +
               8 * ((int)r[i * 8 + 4] - 48) + 4 * ((int)r[i * 8 + 5] - 48) +
               2 * ((int)r[i * 8 + 6] - 48) + 1 * ((int)r[i * 8 + 7] - 48);
  }
  return crc_4;
}

bool check_crc(char *buffer_rx, int ret, int data_start) {
  char crc_val[4];
  char data_buffer[ret];
  for (int i = data_start; i < ret; i++) {
    data_buffer[i - data_start] = buffer_rx[i];
  }

  for (int i = 0; i < 4; i++) {
    crc_val[i] = buffer_rx[i];
  }
  unsigned long crc = crc32(0L, Z_NULL, 0);
  int *crc_cal = compute_crc(data_buffer, crc, ret - data_start);

  // prepocitane crc
  int k = 0;
  for (int i = 0; i < 4; i++) {
    if ((char)crc_cal[i] == crc_val[i]) {
      k += 1;
    }
  }

  if (k == 4) {
    return true;
  } else {
    return false;
  }

  // // // hlavni TODO
  //  radek 273, prosim mrkni, byl uz sem ztracenej
  //  v kazdy funkci(get_hash, get_size, open:file) je implementovany CRCko a
  //  hozene do CRCerror (false je error, true je ok), chce to tam dodelat
  //  poslani nejake zpravy a v cleinotvi pripadne resetnd noo a dal me uz asi
  //  nic nenapada
}
