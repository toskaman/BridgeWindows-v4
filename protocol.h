#ifndef BRIDGE_PROTOCOL_H
#define BRIDGE_PROTOCOL_H

#include <stdint.h>

/*
 * BridgeWindows Protocol Definition v3.0.0
 * Master (Antigravity PC) <---> Agent (Remote Windows 10 x86 PC)
 *
 * Framing:
 * [4 bytes Big-Endian Length] + [UTF-8 JSON-RPC 2.0 Payload]
 */

#define BRIDGE_PROTOCOL_VERSION "4.0.0"  /* v4: mutual auth + session-MAC envelopes + agent registry (no v3 compat) */
#define DEFAULT_BRIDGE_PORT     9876
#define MAX_FRAME_SIZE          (32 * 1024 * 1024)  /* 32 MB hard cap per frame */
#define MAX_PIPE_BUFFER_BYTES   (256 * 1024)        /* 256 KB max stdout / stderr */
#define MAX_IO_CHUNK_BYTES      (256 * 1024)        /* 256 KB chunk for file streaming */
#define MAX_CHUNK_RETRIES       3                   /* Max chunk retransmissions on SHA-256 error */
#define MAX_SCREENSHOT_BYTES    (8 * 1024 * 1024)   /* 8 MB max screenshot buffer */

/* Circular Log Ring Constants (64 KB static footprint in BSS) */
#define LOG_RING_CAPACITY       256
#define LOG_MSG_MAX_LEN         236

/*
 * SWARM-180 / SWARM-189: BINARY CHUNKED TRANSFER PROTOCOL v3.7.0
 * Zero-allocation, high-throughput binary framing over multiplexed TCP
 */
#define BRIDGE_BIN_MAGIC            0xBF        /* Multiplexing discriminator byte */
#define BRIDGE_BIN_VERSION          1
#define BRIDGE_BIN_MAX_CHUNK_SIZE   (64 * 1024) /* 64 KB static cluster buffer */

/* Binary Frame Types */
#define BIN_FRAME_TYPE_CHUNK        0x01
#define BIN_FRAME_TYPE_ACK          0x02
#define BIN_FRAME_TYPE_ABORT        0x03

/* Binary Chunk Header Flags */
#define BIN_FLAG_START              0x00000001  /* Initial chunk of a transfer session */
#define BIN_FLAG_EOF                0x00000002  /* Final chunk: closes file & seals SHA-256 */
#define BIN_FLAG_SYNC               0x00000004  /* Force FlushFileBuffers after write */

/* Binary ACK Status Codes */
#define BIN_ACK_OK                  0x00000000  /* Chunk accepted and written */
#define BIN_ACK_ERR_CRC             0x00000001  /* CRC32 verification failed */
#define BIN_ACK_ERR_IO              0x00000002  /* Win32 WriteFile / SetFilePointer failed */
#define BIN_ACK_ERR_SESSION         0x00000003  /* File ID mismatch or session inactive */
#define BIN_ACK_ERR_SIZE            0x00000004  /* Chunk length exceeds 64 KB limit */
#define BIN_ACK_ERR_INTERNAL        0x00000005  /* Internal CNG / memory error */

#pragma pack(push, 1)

/* 4-Byte Frame Tag (Prefix for demuxing JSON-RPC vs Binary) */
typedef struct {
    uint8_t  magic;       /* 0xBF (BRIDGE_BIN_MAGIC) */
    uint8_t  frame_type;  /* 0x01 = CHUNK, 0x02 = ACK */
    uint8_t  version;     /* Protocol version (1) */
    uint8_t  flags;       /* Reserved / frame flags */
} BridgeBinaryFrameTag;   /* Exactly 4 Bytes */

/* 24-Byte Chunk Header (Precedes raw payload) */
typedef struct {
    uint32_t file_id;     /* 4B: Session file identifier */
    uint32_t flags;       /* 4B: BIN_FLAG_START, BIN_FLAG_EOF, BIN_FLAG_SYNC */
    uint64_t offset;      /* 8B: Target byte offset in destination file */
    uint32_t length;      /* 4B: Payload length following header (<= 64 KB) */
    uint32_t crc32;       /* 4B: IEEE 802.3 CRC32 of payload */
} BridgeBinaryChunkHeader; /* Exactly 24 Bytes */

/* 24-Byte Chunk Acknowledgment */
typedef struct {
    uint32_t file_id;       /* 4B: Echoed session file identifier */
    uint32_t status;        /* 4B: BIN_ACK_OK or error code */
    uint64_t offset;        /* 8B: Acknowledged file offset */
    uint32_t bytes_written; /* 4B: Actual bytes committed to disk */
    uint32_t chunk_crc32;   /* 4B: Echoed/computed CRC32 */
} BridgeBinaryChunkAck;   /* Exactly 24 Bytes */

#pragma pack(pop)

/* JSON-RPC Error Codes */
#define RPC_ERR_AUTH_FAILED      (-32000)
#define RPC_ERR_EXEC_FAILED      (-32010)
#define RPC_ERR_FS_FAILED        (-32020)
#define RPC_ERR_REG_FAILED       (-32030)
#define RPC_ERR_SVC_FAILED       (-32040)
#define RPC_ERR_PROC_FAILED      (-32050)
#define RPC_ERR_GUI_FAILED       (-32060)
#define RPC_ERR_OPT_FAILED       (-32070)
#define RPC_ERR_UPDATE_FAILED    (-32080)
#define RPC_ERR_INVALID_REQ      (-32600)
#define RPC_ERR_METHOD_NOT_FOUND (-32601)
#define RPC_ERR_INVALID_PARAMS   (-32602)
#define RPC_ERR_INTERNAL         (-32603)

#endif /* BRIDGE_PROTOCOL_H */
