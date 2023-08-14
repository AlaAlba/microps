#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

/**
 * IPヘッダ構造体
 * - この構造体のポインタにキャストすることで、バイト列をIPヘッダとみなしてアクセスできる
*/
struct ip_hdr {
    /* バージョン(4bit)とIPヘッダ長(4bit)をまとめて 8bit として扱う */
    uint8_t vhl;
    /* Type Of Service (サービス種別) */
    uint8_t tos;
    /* Total Length (データグラム全長) */
    uint16_t total;
    /* Identification (識別子) */
    uint16_t id;
    /* フラグ(3bit)とフラグメントオフセット(13bit)をまとめて 16bit として扱う */
    uint16_t offset;
    /* Time To Live (生存時間) */
    uint8_t ttl;
    /* Protocol (プロトコル番号) */
    uint8_t protocol;
    /* Header Checksum (ヘッダチェックサム) */
    uint16_t sum;
    /* 送信元IPアドレス */
    ip_addr_t src;
    /* 宛先IPアドレス */
    ip_addr_t dst;
    /* オプション (可変長のため、フレキシブル配列メンバ) */
    uint8_t options[];
};

const ip_addr_t IP_ADDR_ANY         = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST   = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need protect these lists with a mutex */
static struct ip_iface *ifaces;

/**
 * IPアドレスを文字列からネットワークバイトオーダのバイナリ値(ip_addr_t)に変換
 * xxx_pton()･･･Printable text TO Network binary
 * @param [in] *p 文字列
 * @param [in/out] *n バイナリ値
 * @return 結果
*/
int
ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

/**
 * IPアドレスをネットワークバイトオーダのバイナリ値(ip_addr_t)から文字列に変換
 * xxx_ntop()･･･Network binary TO Printable text
*/
char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

/**
 * デバッグ出力
*/
static void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    /* vhl ･･･ 上位4bit = バージョン、下位4bit = IPヘッダ長 */
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    /* IPヘッダ長･･･32bit(4byte)単位の値が格納されているので4倍して8bit(1byte)単位の値にする */
    hlen = hl << 2;
    fprintf(stderr, "       vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "       tos: 0x%02x\n", hdr->tos);
    /* 多バイト長(16bitや32bit)の数値データはバイトオーダの変換が必要 */
    total = ntoh16(hdr->total);
    /* トータル長からIPヘッダ長を引いたものが運んでいるデータ(ペイロード)の長さ */
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    /* offset･･･上位3bit = フラグ、下位13bit = フラグメントオフセット */
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    /* IPアドレスをネットワークバイトオーダのバイナリ値(ip_addr_t)から文字列に変換 */
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;

    /* IPインターフェースのメモリを確保 */
    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    /* インターフェースの種別を示す family の値を設定 */
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    /* Exercise7-3: IPインターフェースにアドレス情報を設定 */
    /* (1) iface->unicast: 引数 unicast を文字列からバイナリ値に変換して設定する */
    /*   - 変換に失敗した場合はエラーを返す (不要になった iface のメモリ解放をわすれずに) */
    if (ip_addr_pton(unicast, &iface->unicast) == -1) {
        errorf("ip_addr_pton() failure, unicast");
        memory_free(iface);
        return NULL;
    }
    /* (2) iface->netmask: 引数 netmask を文字列からバイナリ値に変換して設定する */
    /*    - 変換に失敗した場合はエラーを返す (不要になった iface のメモリ解放を忘れずに) */
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        errorf("ip_addr_pton() failure, netmask");
        memory_free(iface);
        return NULL;
    }
    /* (3) iface->broadcast: iface->unicast と iface->netmask の値から算出して設定する */
    iface->broadcast = (iface->unicast & iface->netmask) | (~iface->netmask);

    return iface;
}

/**
 * IPインターフェースの登録
*/
/* NOTE: must not be call after net_run() */
int
ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    /* Exercise7-4: IPインターフェースの登録 */
    /* (1) デバイスにIPインターフェース (iface) を登録する */
    /*    - エラーが返されたらこの関数もエラーを返す */
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    /* (2) IPインターフェースのリスト (ifaces) の先頭に iface を挿入する */
    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

/**
 * IPインターフェースの検索
*/
struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    /* Exercise7-5: IPインターフェースの検索 */
    /* - インターフェースリスト (ifaces) を巡回 */
    /*   + 引数 addr で指定された IPアドレスをもつインターフェースを返す */
    /* - 合致するインターフェースを発見できなかったら NULL を返す */
    struct ip_iface *entry;
    for (entry = ifaces; entry; entry = entry->next) {
        if (entry->unicast == addr) {
            break;
        }
    }
    return entry;

}

/**
 * IPの入力関数
*/
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    /* 入力データの長さがIPヘッダの最小サイズより小さい場合はエラー */
    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    /* 入力データをIPヘッダ構造体のポインタへキャスト */
    hdr = (struct ip_hdr *)data;

    /* Exercise 6-1: IPデータグラムの検証 */
    /* (1) バージョン
     * IP_VERSION_IPV4 と一致しない場合はエラーメッセージを出して中断
     */
    v = (hdr->vhl & 0xf0) >> 4;
    if (v != IP_VERSION_IPV4) {
        errorf("not IPV4");
        return;
    }

    /* (2) ヘッダ長
     * 入力データの長さ (len) がヘッダ長より小さい場合はエラーメッセージを出して中断
     */
    hlen = (hdr->vhl & 0x0f) << 2; /* IPヘッダ長･･･32bit(4byte)単位の値が格納されているので4倍して8bit(1byte)単位の値にする */
    if (len < hlen) {
        errorf("smaller than header length");
        return;
    }

    /* (3) トータル長
     * 入力データの長さ (len) がトータル長より小さい場合はエラーメッセージを出して中断
     */
    total = ntoh16(hdr->total);
    if (len < total) {
        errorf("smaller than total length");
        return;
    }

    /* (4) チェックサム
     * cksum16() での検証に失敗した場合はエラーメッセージを出力して中断
     */
    if (cksum16((uint16_t *)hdr, hlen, 0) != 0) {
        errorf("checksum error");
        return;
    }

    /* 今回はIPのフラグメントをサポートしないのでフラグメントだったら処理せず中断する */
    /* フラグメントかどうかの判断＝MF(More Flagments)ビットが立っている or フラグメントオフセットに値がある */
    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        errorf("fragments does not support");
        return;
    }

    /* Exercise7-6: IPデータグラムのフィルタリング */
    /* (1) デバイスに紐づくIPインターフェースを取得 */
    /*    - IPインターフェースを取得できなかったら中断する */
    iface = (struct ip_iface *) net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface == NULL) {
        return;
    }
    /* (2) 宛先IPアドレスの検証 */
    /*    - 以下のいずれにも一致しない場合は「他ホスト宛」と判断して中断する（エラーメッセージは出力しない */
    /*     a. インターフェースのユニキャストIPアドレス */
    /*     b. ブロードキャストIPアドレス(255.255.255.255) */
    /*     c. インターフェースが属するサブネットのブロードキャストIPアドレス(xxx.xxx.xxx.255など) */
    if (hdr->dst != iface->unicast && hdr->dst != iface->broadcast && hdr->dst != IP_ADDR_BROADCAST) {
        return;
    }

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", 
        dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);
}

/**
 * IP の初期化
*/
int
ip_init(void)
{
    /* プロトコルスタックに IP の入力関数を登録する */
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}