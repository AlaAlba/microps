#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

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

/**
 * プロトコル構造体
 * IPの上位プロトコルを管理するための構造体
 * ※ struct net_protocol とほぼ同じ
 */
struct ip_protocol {
    /* 次のIPプロトコルへのポインタ */
    struct ip_protocol *next;

    /* IPプロトコルの種別 (IP_PROTOCOL_XXX) */
    uint8_t type;

    /* IPプロトコルの入力関数へのポインタ */
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

const ip_addr_t IP_ADDR_ANY         = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST   = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need protect these lists with a mutex */
static struct ip_iface *ifaces;

/* 登録されているIPプロトコルのリスト */
static struct ip_protocol *protocols;

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
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
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
 * プロトコルの登録
 * @param [in] type IPプロトコルの種別 (IP_PROTOCOL_XXX)
 * @param [in,out] handler IPプロトコルの入力関数へのポインタ
 * @return 結果
 */
/* NOTE: must not be call after net_run() */
int
ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
    struct ip_protocol *entry;

    /* Exercise9-1: 重複登録の確認 */
    /* - プロトコルリスト(protocols) を巡回 */
    /*  - 指定された type のエントリが既に存在する場合はエラーを返す */
    for (entry = protocols; entry; entry = entry->next) {
        if (type == entry->type) {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }

    /* Exercise9-2: プロトコルの登録 */
    /* (1) 新しいプロトコルのエントリ用にメモリを確保 */
    /*   - メモリ確保に失敗したらエラーを返す */
    /* (2) プロトコルリスト(protocols) の先頭に挿入 */
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;

    infof("registered, type=%u", entry->type);
    return 0;
}

/**
 * IPの入力関数
 * @param [in] data データポインタ
 * @param [in] len データサイズ
 * @param [in,out] dev デバイス構造体
*/
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    struct ip_protocol *proto;

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

    /* Exercise9-3: プロトコルの検索 */
    /* - プロトコルリスト (protocols) を巡回 */
    /*  - IPヘッダのプロトコル番号と一致するプロトコルの入力関数を呼び出す (入力関数には IPデータグラムのペイロードを渡す) */
    /*  - 入力関数から戻ったら return する */
    /* - 合致するプロトコルが見つからない場合は何もしない */
    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == hdr->protocol) {
            proto->handler( (uint8_t *)hdr + hlen, total - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }
    /* unsupported protocol */
}

/**
 * デバイスからの送信
*/
static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    /* ARP によるアドレス解決が必要なデバイスのための処理 */
    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        /* 宛先がブロードキャストIPアドレスの場合には ARP によるアドレス解決は行わずに */
        /* そのデバイスのブロードキャストHWアドレスを使う */
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            /* まだ ARP を実装していないのでエラーにしておく */
            errorf("arp does not implement");
            return -1;
        }
    }

    /* Exercise8-4: デバイスから送信 */
    /* - net_device_output() を呼び出してインターフェースに紐づくデバイスから IPデータグラムを送信 */
    /* - net_device_output() の戻り値をこの関数の戻り値として返す */
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

/**
 * IPデータグラムの生成
*/
static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;

    /* Exercise8-3: IPデータグラムの生成 */
    /* (1) IPヘッダの各フィールドに値を設定 */
    /*  - IPヘッダの長さは IP_HDR_SIZE_MIN 固定とする (オプションなし) */
    /*  - TOS=0, TTL=255 とする */
    /*  - チェックサムの計算結果はバイトオーダを変換せずにそのまま固定する 
    　  (ネットワークバイトオーダーのバイト列のチェックサム計算結果はネットワークバイトオーダーで得られる) */
    /*    - チェックサム計算の際、あらかじめチェックサムフィールドに 0 を設定するのを忘れずに */
    hlen = IP_HDR_SIZE_MIN;
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    total = hlen + len;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 255;
    hdr->protocol = protocol;
    hdr->sum = 0; /* あらかじめ 0 設定 */
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0); /* don't convert byteorder */

    /* (2) IPヘッダの直後にデータを配置（コピー）する */
    memcpy(hdr+1, data, len);

    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
        NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    /* 生成した IPデータグラムを実際にデバイスから送信するための関数に渡す */
    return ip_output_device(iface, buf, total, dst);
}

/**
 * IPデータグラム
*/
static uint16_t
ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

/**
 * IP の出力関数
*/
ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    /* まだIPルーティングを実装していないので送信元IPアドレスが指定されない場合はエラーを返す */
    if (src == IP_ADDR_ANY) {
        errorf("ip routing does not implement");
        return -1;
    }
    else {
        /* NOTE: I'll rewrite this block later. */

        /* Exercise8-1: IPインターフェースの検索 */
        /* - 送信元IPアドレス(src)に対応するIPインターフェースを検索 */
        /*    - インターフェースが見つからない場合はエラーを返す */
        iface = ip_iface_select(src);
        if (iface == NULL) {
            errorf("src ip address not found.");
            return -1;
        }

        /* Exercise8-2: 宛先へ到達可能か確認 */
        /* - 宛先アドレス(dst) が以下の条件に合致しない場合エラーを返す(到達不能) */
        /* インターフェースのネットワークアドレスの範囲に含まれる */
        /* ブロードキャストIPアドレス(255.255.255.255) */
         if (
            ((dst & iface->netmask) != (iface->unicast & iface->netmask))
            && (dst != IP_ADDR_BROADCAST)
        ) {
            errorf("not reached, dst=%s", ip_addr_ntop(src, addr, sizeof(addr)));
            return -1;
        }
    }

    /* フラグメンテーションをサポートしないので MTU を超える場合はエラーを返す */
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too long, dev=%s, mtu=%u < %zu",
            NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }

    /* IPデータグラムのIDを採番 */
    id = ip_generate_id();
    
    /* IPデータグラムを生成して出力する */
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
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