#include "pins.h"
#include <SPI.h>
#include <MFRC522.h>

MFRC522 mfrc522(SS_PIN, RST_PIN);

static void print_uid_hex_line() {
  Serial.print("UID:");
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i] < 0x10) Serial.print('0');
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();
}

static bool read_ntag215_user_mem(MFRC522& r, uint8_t* out, size_t outCap, size_t& outLen) {
  const uint16_t USER_BYTES = 504; // NTAG215 user memory
  if (outCap < USER_BYTES) return false;
  outLen = 0;

  byte tmp[18]; // 16 data bytes (4 pages) per read
  for (byte page = 4; outLen < USER_BYTES && page <= 129; page += 4) {
    byte size = sizeof(tmp);
    MFRC522::StatusCode st = r.MIFARE_Read(page, tmp, &size);
    if (st != MFRC522::STATUS_OK) return false;
    size_t toCopy = min((size_t)16, (size_t)(USER_BYTES - outLen));
    memcpy(out + outLen, tmp, toCopy);
    outLen += toCopy;
  }
  return outLen == USER_BYTES;
}

static void send_tag_dump(const uint8_t* mem, size_t len) {
  Serial.println("TAG_BEGIN");
  print_uid_hex_line();
  Serial.print("LEN:"); Serial.println((unsigned)len);
  Serial.print("HEX:");
  for (size_t i = 0; i < len; ++i) {
    uint8_t b = mem[i];
    if (b < 0x10) Serial.print('0');
    Serial.print(b, HEX);
  }
  Serial.println();
  Serial.println("TAG_END");
}

static void ensure_cc_configured(MFRC522& r) {
  byte tmp[18]; byte size = sizeof(tmp);
  if (r.MIFARE_Read(3, tmp, &size) != MFRC522::STATUS_OK) return;
  if (tmp[0] != 0xE1) { // NDEF CC Magic
    byte cc[4] = { 0xE1, 0x10, 0x3F, 0x00 }; // NTAG215: 504 bytes -> MLen 0x3F
    (void)r.MIFARE_Ultralight_Write(3, cc, 4);
  }
}

static uint8_t pick_uri_prefix_code(const char* url, const char*& suffix) {
  if (!url) { suffix = ""; return 0; }
  if (!strncmp(url, "https://www.", 12)) { suffix = url + 12; return 0x02; }
  if (!strncmp(url, "http://www.", 11))  { suffix = url + 11; return 0x01; }
  if (!strncmp(url, "https://", 8))      { suffix = url + 8;  return 0x04; }
  if (!strncmp(url, "http://", 7))       { suffix = url + 7;  return 0x03; }
  if (!strncmp(url, "mailto:", 7))       { suffix = url + 7;  return 0x06; }
  if (!strncmp(url, "tel:", 4))          { suffix = url + 4;  return 0x05; }
  suffix = url; return 0x00;
}

static bool t2_write_pages(MFRC522& r, byte startPage, const uint8_t* data, size_t len) {
  byte page = startPage;
  uint8_t buf[4];
  for (size_t i = 0; i < len; i += 4, page++) {
    buf[0] = (i+0 < len) ? data[i+0] : 0x00;
    buf[1] = (i+1 < len) ? data[i+1] : 0x00;
    buf[2] = (i+2 < len) ? data[i+2] : 0x00;
    buf[3] = (i+3 < len) ? data[i+3] : 0x00;
    MFRC522::StatusCode st = r.MIFARE_Ultralight_Write(page, buf, 4);
    if (st != MFRC522::STATUS_OK) return false;
  }
  return true;
}

static bool write_ndef_uri(MFRC522& r, const char* url) {
  ensure_cc_configured(r);
  const char* suffix; uint8_t code = pick_uri_prefix_code(url, suffix);
  size_t suffixLen = strlen(suffix);

  // NDEF record: D1 01 <PLEN> 55 <code> <suffix>
  uint8_t recHdr = 0xD1; // MB/ME/SR, TNF=Well-Known(0x01)
  uint8_t typeLen = 0x01;
  uint8_t payLen  = 1 + (uint8_t)suffixLen;
  uint8_t typeU   = 0x55; // 'U'

  size_t ndefLen = 1 + 1 + 1 + 1 + payLen;
  uint8_t buf[1 + 1 + 5 + 255 + 1];
  size_t k = 0;
  buf[k++] = 0x03;                 // NDEF TLV
  buf[k++] = (uint8_t)ndefLen;     // short length
  buf[k++] = recHdr;
  buf[k++] = typeLen;
  buf[k++] = payLen;
  buf[k++] = typeU;
  buf[k++] = code;
  memcpy(&buf[k], suffix, suffixLen); k += suffixLen;
  buf[k++] = 0xFE;                 // Terminator

  return t2_write_pages(r, 4, buf, k);
}

// Handlie serial commands
static bool handle_serial_command_and_echo(uint8_t* mem, size_t memCap, size_t& memLen) {
  if (!Serial.available()) return false;
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.startsWith("WRITEURI ")) {
    String url = line.substring(9);
    url.trim();
    bool ok = write_ndef_uri(mfrc522, url.c_str());
    Serial.println(ok ? "ACK:WRITEURI" : "ERR:WRITEURI");
    if (ok && read_ntag215_user_mem(mfrc522, mem, memCap, memLen)) {
      send_tag_dump(mem, memLen); // confirm new bytes
    }
    return true;
  }
  return false;
}

void setup() {
  Serial.begin(115200);
  while (!Serial) { delay(10); }

  SPI.setMISO(MISO_PIN);
  SPI.setMOSI(MOSI_PIN);
  SPI.setSCK(SCK_PIN);
  SPI.begin();
  mfrc522.PCD_Init();

  Serial.println("READY");
}

void loop() {
  if (!mfrc522.PICC_IsNewCardPresent()) return;
  if (!mfrc522.PICC_ReadCardSerial())   return;

  // Read & send raw bytes
  uint8_t mem[504]; size_t memLen = 0;
  if (read_ntag215_user_mem(mfrc522, mem, sizeof(mem), memLen)) {
    send_tag_dump(mem, memLen);
  }

  // Give host short window to send WRITEURI while card is still present
  unsigned long until = millis() + 3000; // 3s window
  while (millis() < until) {
    if (handle_serial_command_and_echo(mem, sizeof(mem), memLen)) {
      until = millis() + 1000; // slight extension after write
    }
    delay(5);
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  delay(150);
}
