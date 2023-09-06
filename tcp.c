#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "tcp.h"

/* TCP ヘッダのフラグフィールドの値 */
/* コネクションの正常な終了を要求することを示す。 */
#define TCP_FLG_FIN 0x01
/* コネクションの確率を要求することを示す。 */
#define TCP_FLG_SYN 0x02
/* コネクションが強制的に切断されることを示す。 */
#define TCP_FLG_RST 0x04
/* 受信したデータをバッファリングせずに即座にアプリケーションに渡すことを示す(Push)。 */
#define TCP_FLG_PSH 0x08
/* 確認応答番号のフィールドが有効であることを示す。コネクション確立時以外は値が１ */
#define TCP_FLG_ACK 0x10
/* 緊急に処理すべきデータが含まれていることを示す。(Urgent) */
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

/* TCP 疑似ヘッダ構造体(チェックサム計算時に使用する) */
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

/* TCP ヘッダ構造体 */
struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

/**
 * TCP Flag を文字列に変換
 * Network To ASCII
 * @param [in] type TCP Flag
 * @return TCP Flag(ASCII)
 */
static char *
tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
        TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

/**
 * デバッグ出力
 * @param [in] data TCPデータポインタ
 * @param [in] len データサイズ
 */
static void
tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * TCP セグメントの入力関数
 * @param [in,out] data
 * @param [in] len データサイズ
 * @param [in] src
 * @param [in] dst
 * @param [in,out] iface
 */
static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    /* ヘッダサイズに満たないデータはエラーとする */
    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;

    /* Exercise22-3: チェックサムの検証 */
    /* UDPと同様に疑似ヘッダを含めて計算する */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    /* Exercise22-4: アドレスのチェック */
    /* 送信元または宛先どちらかのアドレスがブロードキャストアドレスだった場合にはエラーメッセージを出力して中断する */
    if (src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST) {
        /* TCPはコネクション型なので、ブロードキャストとマルチキャストはできない */
        errorf("Broadcast and multicast are not possible. src=%s, dst=%s",
            ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)));
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    tcp_dump(data, len);
    return;

}

/**
 * TCP の初期化
 * @return 結果
 */
int
tcp_init(void)
{
    /* Exercise22-1: IP の上位プロトコルとして TCP を登録する */
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}