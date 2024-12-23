#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <nfc/nfc.h>
#include "mifare.h"
#define SAK_FLAG_ATS_SUPPORTED 0x20

#define MAX_FRAME_LEN 264

extern void warnx (const char *__format, ...)
     __attribute__ ((__format__ (__printf__, 1, 2)));

/**
 * @macro ERR
 * @brief Print a error message
 */
#ifdef DEBUG
#  define ERR(...) do { \
    warnx ("ERROR %s:%d", __FILE__, __LINE__); \
    warnx ("    " __VA_ARGS__ ); \
  } while (0)
#else
#  define ERR(...)  warnx ("ERROR: " __VA_ARGS__ )
#endif

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
static size_t szRx = sizeof(abtRx);
static uint8_t abtAtqa[2];
static nfc_device *pnd;
static uint8_t uiBlocks = 0x3f;

bool    quiet_output = false;
bool    iso_ats_supported = false;

// ISO14443A Anti-Collision Commands
uint8_t  abtReqa[1] = { 0x26 };
uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };
#define CASCADE_BIT 0x04

// special unlock command
uint8_t  strangeWupa[1] = { 0x40 };
uint8_t  chineseBackdoorTest[1] = { 0x43 };
uint8_t  Halt[4] = { 0x50, 0x00, 0x00, 0x00 }; //57cd
uint8_t  abtWipe[1] = { 0x41 };
uint8_t  abtWrite[4] = { 0xa0,  0x00,  0x00,  0x00 };
uint8_t  abtData[18] = { 0xaa,  0xbb,  0xcc,  0xdd,  0x00,  0x08,  0x04,  0x00,  0x46,  0x59,  0x25,  0x58,  0x49,  0x10,  0x23,  0x02,  0x00,  0x00 }; //869a
uint8_t  abtBlank[18] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x36, 0xCC };
static mifare_classic_tag mtDump;

void
print_hex(const uint8_t *pbtData, const size_t szBytes)
{
    size_t  szPos;

    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }
    printf("\n");
}

void
print_hex_bits(const uint8_t *pbtData, const size_t szBits)
{
    uint8_t uRemainder;
    size_t  szPos;
    size_t  szBytes = szBits / 8;

    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }

    uRemainder = szBits % 8;
    // Print the rest bits
    if (uRemainder != 0) {
        if (uRemainder < 5)
            printf("%01x (%d bits)", pbtData[szBytes], uRemainder);
        else
            printf("%02x (%d bits)", pbtData[szBytes], uRemainder);
    }
    printf("\n");
}


static  bool
transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
  uint32_t cycles = 0;
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex_bits(pbtTx, szTxBits);
  }

  if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
    return false;

  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex_bits(abtRx, szRxBits);
  }

  // Succesful transfer
  return true;
}


static  bool
transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  uint32_t cycles = 0;
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex(pbtTx, szTx);
  }
  int res;

  // Transmit the command bytes
  if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
    return false;

  szRx = res;
  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex(abtRx, szRx);
  }

  // Succesful transfer
  return true;
}

static bool
is_trailer_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock + 1) % 4 == 0);
  else
    return ((uiBlock + 1) % 16 == 0);
}

static void
print_usage(char *argv[])
{
  printf("Usage: %s [OPTIONS]\n", argv[0]);
  printf("Options:\n");
  printf("\t-h\tHelp. Print this message.\n");
  printf("\t-q\tQuiet mode. Suppress output of READER and EMULATOR data (improves timing).\n");
}

void
iso14443a_crc(uint8_t *pbtData, size_t szLen, uint8_t *pbtCrc)
{
    uint32_t wCrc = 0x6363;

  do {
    uint8_t  bt;
    bt = *pbtData++;
    bt = (bt ^ (uint8_t)(wCrc & 0x00FF));
    bt = (bt ^ (bt << 4));
    wCrc = (wCrc >> 8) ^ ((uint32_t) bt << 8) ^ ((uint32_t) bt << 3) ^ ((uint32_t) bt >> 4);
  } while (--szLen);

  *pbtCrc++ = (uint8_t)(wCrc & 0xFF);
  *pbtCrc = (uint8_t)((wCrc >> 8) & 0xFF);
}


void
iso14443a_crc_append(uint8_t *pbtData, size_t szLen)
{
  iso14443a_crc(pbtData, szLen, pbtData + szLen);
}


static void
write_unlocked(void) 
{
  iso14443a_crc_append(Halt, 2);
  transmit_bytes(Halt, 4);

  // Send the 7 bits of "Chinese wakeup"
  if (!transmit_bits(strangeWupa, 7)) {
    printf("This is NOT a backdoored rewritable UID chinese card\n");
    exit(EXIT_SUCCESS);
  }
  memcpy(abtAtqa, abtRx, 2);

  // Strange backdoored command that is not implemented in normal Mifare
  bool success = transmit_bytes(chineseBackdoorTest, 1);
  if (success) {
    printf("This is backdoored rewritable UID chinese card\n");
  } else {
    printf("This is NOT a backdoored rewritable UID chinese card\n");
  }
  for(int i = 0; i <= 63; i++) {
    abtWrite[1] = i;
    iso14443a_crc_append(abtWrite, 2);
    transmit_bytes(abtWrite, 4);
    uint8_t data[18];
    if(!is_trailer_block(i)) {
      memcpy(data, mtDump.amb[i].mbd.abtData, sizeof(mtDump.amb[i].mbd.abtData));
    } else {
      memcpy(data, mtDump.amb[i].mbt.abtKeyA, sizeof(mtDump.amb[i].mbt.abtKeyA));
      memcpy(data + sizeof(mtDump.amb[i].mbt.abtKeyA), mtDump.amb[i].mbt.abtAccessBits, sizeof(mtDump.amb[i].mbt.abtAccessBits));
      memcpy(data + sizeof(mtDump.amb[i].mbt.abtKeyA) + sizeof(mtDump.amb[i].mbt.abtAccessBits), mtDump.amb[i].mbt.abtKeyB, sizeof(mtDump.amb[i].mbt.abtKeyB));
    }
    iso14443a_crc_append(data, 16);
    transmit_bytes(data, 18); 
  }
}

int
main(int argc, char *argv[])
{
  int arg;

  // Get commandline options
  for (arg = 1; arg < argc; arg++) {
    if (0 == strcmp(argv[arg], "-h")) {
      print_usage(argv);
      exit(EXIT_SUCCESS);
    } else if (0 == strcmp(argv[arg], "-q")) {
      quiet_output = true;
    } else if (strlen(argv[arg]) > 2) {
      printf("Dump from file: %s", argv[arg]);
    } else {
      ERR("%s is not supported option.", argv[arg]);
      print_usage(argv);
      exit(EXIT_FAILURE);
    }
  }

  FILE *pfDump = fopen(argv[1], "rb");

  if (pfDump == NULL) {
    printf("Could not open dump file: %s\n", argv[1]);
    exit(EXIT_FAILURE);
  }

  if (fread(&mtDump, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfDump) != (uiBlocks + 1) * sizeof(mifare_classic_block)) {
    printf("Could not read dump file: %s\n", argv[1]);
    fclose(pfDump);
    exit(EXIT_FAILURE);
  }
  fclose(pfDump);

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC reader
  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Initialise NFC device as "initiator"
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Disable 14443-4 autoswitching
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n\n", nfc_device_get_name(pnd));

  write_unlocked();

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
