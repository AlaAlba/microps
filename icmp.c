#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

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

    /* デバッグ出力 */
    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    icmp_dump(data, len);

    /* EchoReply メッセージの送信 */
    switch (hdr->type) {
        case ICMP_TYPE_ECHO:
            /* Responds with the address of the received interface. */

            /* Exercise11-3: ICMP の出力関数を呼び出す */
            /* - メッセージ種別に ICMP_TYPE_ECHO_REPLY を指定 */
            /* - その他のパラメータは受信メッセージに含まれる値をそのまま渡す */
            /* - 送信元は Echo メッセージを受信したインターフェース (iface) のユニキャストアドレス */
            /* - 宛先は Echo メッセージの送信元 (src) */
            icmp_output(ICMP_TYPE_ECHOREPLY, hdr->code, hdr->values, (uint8_t *)(hdr + 1), len - sizeof(*hdr), iface->unicast, src);
            break;
        default:
            /* ignore */
            break;
    }
}

/**
 * ICMP の出力関数
 * @param [in] type 種別
 * @param [in] code コード
 * @param [in] values Message Specific Field ※ネットワークバイトオーダー
 * @param [in] data データのポインタ
 * @param [in] len データサイズ
 * @param [in] src 送信元IPアドレス
 * @param [in] dst 宛先IPアドレス
 * @return 結果
 */
int
icmp_output(uint8_t type, uint8_t code, uint32_t values, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    uint8_t buf[ICMP_BUFSIZ]; /* ICMPメッセージ構成用のバッファ */
    struct icmp_hdr *hdr;
    size_t msg_len; /* ICMPメッセージの長さ (ヘッダ＋データ) */
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    hdr = (struct icmp_hdr *)buf; /* バッファの先頭箇所を ICMPヘッダでキャスト */

    /* Exercise11-1: ICMPメッセージの生成 */
    /* - ヘッダの各フィールドに値を設定 */
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->values = values;
    /* - ヘッダの直後にデータを配置(コピー) */
    memcpy(hdr+1, data, len);
    /* - ICMPメッセージ全体の長さを計算して msg_len に格納する */
    msg_len = sizeof(*hdr) + len;
    /* - チェックサムを計算してチェックサムフィールドに格納(あらかじめチェックサムフィールドを0にしておくのを忘れずに) */
    hdr->sum = cksum16((uint16_t *)hdr, msg_len, 0);

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), msg_len);
    icmp_dump((uint8_t *)hdr, msg_len);

    /* Exercise11-2: IPの出力関数を呼び出してメッセージを送信 */
    /* - 戻り値をそのままこの関数の戻り値として返す */
    return ip_output(IP_PROTOCOL_ICMP, buf, msg_len, src, dst);
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
