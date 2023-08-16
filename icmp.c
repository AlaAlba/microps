#include <stdint.h>
#include <stddef.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

/**
 * ICMPヘッダ構造体
 */
struct icmp_hdr {
    /* Type (種別) */
    uint8_t type;
    /* Code (コード) */
    uint8_t code;
    /* Checksum (チェックサム) */
    uint16_t sum;
    /* Message Specific Field (メッセージ毎に扱いが異なるフィールド) */
    uint32_t values;
};

/**
 * ICMP Echo/EchoReply メッセージ構造体
 * (メッセージ種別が判別した段階でこちらにキャストする)
 */
struct icmp_echo {
    /* Type (種別) */
    uint8_t type;
    /* Code (コード) */
    uint8_t code;
    /* Checksum (チェックサム) */
    uint16_t sum;
    /* Identifier */
    uint16_t id;
    /* Sequence Number */
    uint16_t seq;
};

/**
 * ICMP Type を文字列に変換
 * Network To ASCII
 * @param [in] type ICMP Type (Network binary)
 * @return ICMP Type (ASCII)
 */
static char *
icmp_type_ntoa(uint8_t type) {
    switch (type) {
    case ICMP_TYPE_ECHOREPLY:
        return "EchoReply";
    case ICMP_TYPE_DEST_UNREACH:
        return "DestinationUnreachable";
    case ICMP_TYPE_SOURCE_QUENCH:
        return "SourceQuench";
    case ICMP_TYPE_REDIRECT:
        return "Redirect";
    case ICMP_TYPE_ECHO:
        return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
        return "TimeExceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
        return "ParameterProblem";
    case ICMP_TYPE_TIMESTAMP:
        return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:
        return "TimestampReply";
    case ICMP_TYPE_INFO_REQUEST:
        return "InformationRequest";
    case ICMP_TYPE_INFO_REPLY:
        return "InformationReply";
    }
    return "Unknown";
}

/**
 * デバッグ出力
 * @param [in] data IPのデータ部ポインタ
 * @param [in] len データ長
 */
static void
icmp_dump(const uint8_t *data, size_t len)
{
    struct icmp_hdr *hdr;
    struct icmp_echo *echo;

    /* 全メッセージ共通のフィールド */
    flockfile(stderr);
    hdr = (struct icmp_hdr *)data;
    fprintf(stderr, "       type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, "       code: %u\n", hdr->code);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    switch (hdr->type) {
    /* Echo/EchoReply の場合には詳細を出力 */
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
        echo = (struct icmp_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
        fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
        break;
    /* その他のメッセージの場合には 32bit 値をそのまま出力 */
    default:
        fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->values));
        break;
    }
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * ICMP の入力関数
 * @param [in] data データポインタ
 * @param [in] len データサイズ
 * @param [in] src 送信元IPアドレス
 * @param [in] dst 宛先IPアドレス
 * @param [in,out] iface IPインターフェース
 */
void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct icmp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    /* Exercise10-1: ICMPメッセージの検証 */
    /* - 入力データの長さの確認 */
    /*  - ICMPヘッダサイズ未満の場合はエラーメッセージを出力して中断 */
    /* - チェックサムの検証 */
    /*  - 検証に失敗した場合はエラーメッセージを出力して中断 */
    if (len < ICMP_HDR_SIZE) {
        errorf("ICMP Header size min length error");
        return;
    }
    hdr = (struct icmp_hdr *)data;
    if (cksum16((uint16_t *)hdr, len, 0) != 0) {
        errorf("checksum error, sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)data, len, -hdr->sum)));
        return;
    }

    /* このステップでは登録した入力関数が呼び出されたことが分かればいいのでデバッグ出力のみ */
    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    icmp_dump(data, len);
}

/**
 * ICMP の初期化
 * ICMP の入力関数を IP に登録
 */
int
icmp_init(void)
{
    /* Exercise9-4: ICMP の入力関数 (icmp_input) を IP に登録 */
    /* - プロトコル番号は ip.h に定義してある定数を使う */
    if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
