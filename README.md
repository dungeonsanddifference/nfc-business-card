sequenceDiagram
    autonumber
    participant R as RC522 Reader
    participant M as RP2350
    participant P as Python Host (pyserial)

    M->>R: Poll for tag (PICC_IsNewCardPresent)
    R-->>M: Card detected
    M->>R: Select + read UID (PICC_ReadCardSerial)
    R-->>M: UID bytes

    loop Read user memory pages (4..129, 504 bytes total)
        M->>R: MIFARE_Read(page)
        R-->>M: 16 bytes (4 pages)
    end

    M->>P: Stream raw frame over USB CDC\nTAG_BEGIN\nUID:<hex>\nLEN:504\nHEX:<...>\nTAG_END
    P->>P: Parse TLVs (Type 2), locate NDEF TLV
    alt NDEF present
        P->>P: Parse NDEF records (URI/Text/…)
        P->>P: Print records to console
    else No NDEF TLV/records
        P->>M: "WRITEURI https://example.com/hello"
        Note right of M: Ensure CC (page 3: E1 10 3F 00)\nBuild NDEF TLV (D1 01 <len> 55 <code> <suffix>)
        loop Write TLV to pages starting at 4
            M->>R: MIFARE_Ultralight_Write(page, 4 bytes)
            R-->>M: Status OK
        end
        M-->>P: "ACK:WRITEURI"
        loop Re-read user memory (pages 4..129)
            M->>R: MIFARE_Read(page)
            R-->>M: 16 bytes
        end
        M->>P: Stream updated frame\nTAG_BEGIN … TAG_END
        P->>P: Parse and confirm records
    end

    M->>R: PICC_HaltA(), PCD_StopCrypto1()
