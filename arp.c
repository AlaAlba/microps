#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifndef __USE_MISC
#define __USE_MISC /* TODO: 暫定 timercmp用 intelisenceが効かない */
#endif

#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
/* ハードウェアアドレス種別：Ethernet */
#define ARP_HDR_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
/* プロトコルアドレス種別：IP */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY    2

#define ARP_CACHE_SIZE  32
#define ARP_CACHE_TIMEOUT 30 /* seconds */

/* ARP キャッシュの状態を表す定数 */
#define ARP_CACHE_STATE_FREE        0
#define ARP_CACHE_STATE_INCOMPLETE  1
#define ARP_CACHE_STATE_RESOLVED    2
#define ARP_CACHE_STATE_STATIC      3

/**
 * ARP ヘッダ構造体
 */
struct arp_hdr {
    /* Hardware Address Space (ハードウェアアドレス種別) */
    uint16_t hrd;
    /* Protocol Address Space (プロトコルアドレス種別) */
    uint16_t pro;
    /* Hardware Address Length (ハードウェアアドレス長)*/
    uint8_t hln;
    /* Protocol Address Length (プロトコルアドレス長) */
    uint8_t pln;
    /* Operation Code (オペレーションコード) */
    uint16_t op;
};

/**
 * (Ethernet/IPペアのための)ARP メッセージ構造体
 */
struct arp_ether_ip {
    /* ARP ヘッダ */
    struct arp_hdr hdr;
    /* Sender Hardware Address (送信元ハードウェアアドレス) */
    uint8_t sha[ETHER_ADDR_LEN];
    /* Sender Protocol Address (送信元プロトコルアドレス) */
    uint8_t spa[IP_ADDR_LEN];
    /* Target Hardware Address (ターゲット・ハードウェアアドレス) */
    uint8_t tha[ETHER_ADDR_LEN];
    /* Target Protocol Address (ターゲット・プロトコルアドレス) */
    uint8_t tpa[IP_ADDR_LEN];
};

/**
 * ARP キャッシュ構造体
 */
struct arp_cache {
    /* キャッシュの状態 */
    unsigned char state;
    /* プロトコルアドレス */
    ip_addr_t pa;
    /* ハードウェアアドレス */
    uint8_t ha[ETHER_ADDR_LEN];
    /* 最終更新時刻 */
    struct timeval timestamp;
};

static mutex_t mutex = MUTEX_INITIALIZER;
/* ARP キャッシュの配列 (ARP テーブル) */
static struct arp_cache caches[ARP_CACHE_SIZE];

/**
 * ARP Operation Code を文字列に変換
 * Network To ASCII
 * @param [in] type ARP Operation Code
 * @return ARP Operation Code(ASCII)
 */
static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

/**
 * デバッグ出力
 * @param [in] data データポインタ
 * @param [in] len データサイズ
 */
static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    /* ここでは Ethernet/IP ペアのメッセージとみなす */
    message = (struct arp_ether_ip *)data;
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "        hln: %u\n", message->hdr.hln);
    fprintf(stderr, "        pln: %u\n", message->hdr.pln);
    fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    
    /* ハードウェアアドレス(sha/tha) ･･･ Ethernetアドレス(MACアドレス) */
    /* プロトコルアドレス(spa/tpa) ･･･ IPアドレス */
    fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    /* spa が uint8_t[4] なので一旦 memcpy() で ip_addr_t の変数へ取り出す */
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    /* tpa も同様に memcpy() で ip_addr_t の変数へ取り出す */
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * ARP Cache
 * NOTE: ARP Cache functions must be called after mutex locked
 */

/**
 * ARP キャッシュの削除
 * @param [in,out] cache ARP キャッシュ
 */
static void
arp_cache_delete(struct arp_cache *cache)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    /* Exercise14-1: キャッシュのエントリを削除する */
    /* - state は未使用 (FREE) の状態にする */
    cache->state = ARP_CACHE_STATE_FREE;
    /* - 各フィールドを 0 にする */
    memset(cache->ha, 0, ETHER_ADDR_LEN);
    cache->pa = 0;
    /* - timestamp は timerclear() でクリアする */
    timerclear(&cache->timestamp);
}

/**
 * ARP キャッシュの領域確保
 * @return ARPキャッシュエントリ
 */
static struct arp_cache *
arp_cache_alloc(void)
{
    struct arp_cache *entry, *oldest = NULL;

    /* ARP キャッシュのテーブルを巡回 */
    for (entry = caches; entry < tailof(caches); entry++) {
        /* 使用されていないエントリを探す */
        if (entry->state == ARP_CACHE_STATE_FREE) {
            return entry;
        }
        /* 空きが無かった時のために一番古いエントリも一緒に探す */
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
            oldest = entry;
        }
    }
    /* 空きが無かったら一番古いエントリを返す */
    /* 現在登録されている内容を削除する */
    arp_cache_delete(oldest);
    return oldest;
}

/**
 * ARP キャッシュの検索
 * @param [in] pa プロトコルアドレス
 * @return ARP キャッシュ
 */
static struct arp_cache *
arp_cache_select(ip_addr_t pa)
{
    /* Exercise14-2: キャッシュの中からプロトコルアドレスが一致するエントリを探して返す */
    /* - 念のため FREE 状態ではないエントリの中から探す */
    /* - 見つからなかったら NULL を返す */
    struct arp_cache *entry;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa) {
            return entry;
        }
    }
    return NULL;
}

/**
 * ARP キャッシュの更新
 * @param [in] pa プロトコルアドレス
 * @param [in] ha ハードウェアアドレス
 * @return ARP キャッシュ
 */
static struct arp_cache *
arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    /* Exercise14-3: キャッシュに登録されている情報を更新する */
    /* (1) arp_cache_select() でエントリを検索する */
    cache = arp_cache_select(pa);
    /* - 見つからなかったらエラー(NULL) を返す */
    if (!cache) {
        return NULL;
    }
    /* (2) エントリの情報を更新する */
    memcpy(&cache->ha, ha, sizeof(ETHER_ADDR_LEN));
    /* cache->pa = pa; */ /* pa で検索しているので同じ値 */
    /* - state は解決済み(RESOLVED)の状態にする */
    cache->state = ARP_CACHE_STATE_RESOLVED;
    /* - timestamp は gettimeofday() で設定する */
    gettimeofday(&cache->timestamp, NULL);

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

/**
 * ARP キャッシュの登録
 * @param [in] pa プロトコルアドレス
 * @param [in] ha ハードウェアアドレス
 * @return ARP キャッシュ
 */
static struct arp_cache *
arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    /* Exercise14-4: キャッシュに新しくエントリを登録する */
    /* (1) arp_cache_alloc() でエントリの登録スペースを確保する */
    cache = arp_cache_alloc();
    /* - 確保できなかったらエラー(NULL)を返す */
    if (!cache) {
        return NULL;
    }
    /* (2) エントリの情報を設定する */
    memcpy(cache->ha, ha, sizeof(ETHER_ADDR_STR_LEN));
    cache->pa = pa;
    /* - state は解決済み(RESOLVED) の状態にする */
    cache->state = ARP_CACHE_STATE_RESOLVED;
    /* - timestamp は gettimeofday() で設定する */
    gettimeofday(&cache->timestamp, NULL);

    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

/**
 * ARP 要求の送信関数
 * @param [in,out] iface インターフェース構造体のポインタ
 * @param [in] tpa ターゲットプロトコルアドレス
 */
static int
arp_request(struct net_iface *iface, ip_addr_t tpa)
{
    struct arp_ether_ip request;

    /* Exercise15-2: ARP 要求のメッセージを生成する */
    request.hdr.hrd = hton16(ARP_HDR_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);

    // 送信元
    memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    // 目標
    // 目標MACアドレスは分からないので「0」が格納される
    memset(request.tha, 0, sizeof(ETHER_ADDR_LEN));
    memcpy(request.tpa, &tpa, sizeof(IP_ADDR_LEN));

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
    arp_dump((uint8_t *)&request, sizeof(request));

    /* Exerice15-3: デバイスの送信関数を呼び出して ARP 要求のメッセージを送信する */
    /* - 宛先はデバイスに設定されているブロードキャストアドレスとする */
    /* - デバイスの送信関数の戻り値をこの関数の戻り値とする */
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&request, sizeof(request), iface->dev->broadcast);
}

/**
 * ARP 応答の送信
 * @param [in,out] iface
 * @param [in] tha
 * @param [in] tpa
 * @param [in] dst
 * @return
 */
static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;

    /* Exercise13-3: ARP 応答メッセージの生成 */
    /* ※ host to network に変換が必要 */
    reply.hdr.hrd = hton16(ARP_HDR_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    /* - spa/sha ･･･ インターフェースの IP アドレスと紐づくデバイスの MAC アドレスを設定する */
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    /* - tpa/tha ･･･ ARP 要求を送ってきたノードの IP アドレスと MAC アドレスを設定する */
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    /* デバイスから ARP メッセージを送信 */
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

/**
 * ARP メッセージの受信
 * @param [in] data データポインタ
 * @param [in] len データ長
 * @param [in,out] dev デバイス構造体ポインタ
 */
static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;
    int merge = 0; /* 更新の可否を示すフラグ */

    /* 期待する ARP メッセージのサイズより小さかったらエラーを返す */
    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }
    msg = (struct arp_ether_ip *)data;

    /* Exercise13-1: 対応可能なアドレスペアのメッセージのみ受け入れる */
    /* (1) ハードウェアアドレスのチェック */
    /* - アドレス種別とアドレス長が Ethernet と合致しなければ中断 */
    if (ntoh16(msg->hdr.hrd) != ARP_HDR_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("not match hardware address = ETHER");
        return;
    }
    /* (2) プロトコルアドレスのチェック */
    /* - アドレス種別とアドレス長が IP と合致しなければ中断 */
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("not match protocol address = IP");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);
    /* spa/tpa を memcpy() で ip_addr_t の変数へ取り出す */
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    /* キャッシュへのアクセスをミューテックスで保護 */
    mutex_lock(&mutex);
    /* ARP メッセージを受信したら、まず送信元アドレスのキャッシュ情報を更新する（更新なので未登録の場合には失敗する) */
    if (arp_cache_update(spa, msg->sha)) {
        /* updated */
        merge = 1;
    }
    /* アンロック */
    mutex_unlock(&mutex);

    /* デバイスに紐づく IP インターフェースを取得する */
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    /* ARP 要求のターゲットプロトコルアドレスと一致するか確認 */
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        /* 先の処理で送信元アドレスのキャッシュ情報が更新されていなかったら（まだ未登録だったら） */
        if (!merge) {
            /* ミューテックスの保護を忘れずに */
            mutex_lock(&mutex);
            /* 送信元アドレスのキャッシュ情報を新規登録する */
            arp_cache_insert(spa, msg->sha);
            mutex_unlock(&mutex);
        }
        /* Exercise13-2: ARP要求への応答 */
        /* - メッセージ種別が ARP 要求だったら arp_reply() を呼び出して ARP 応答を送信する */
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) { /* ※ network to host に変換が必要 */
            /* 送信元のハードウェアアドレス(sha), 送信元プロトコルアドレス(spa), */
            /* ターゲットプロトコルアドレス(tpa) を利用して送信元に対して応答する */
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

/**
 * アドレス解決
 * @param [in,out] iface インターフェース構造体のポインタ
 * @param [in] pa プロトコルアドレス
 * @param [in,out] ha ハードウェアアドレスのポインタ
 * @return 結果
 */
int
arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    /* 念のため、物理デバイスと論理インターフェースがそれぞれ Ethernet と IP であることを確認 */
    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware type");
        return ARP_RESOLVE_ERROR;
    }
    if (iface->family != NET_IFACE_FAMILY_IP) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }
    /* ARP キャッシュへのアクセスを mutex で保護 (アンロックを忘れずに) */
    mutex_lock(&mutex);
    cache = arp_cache_select(pa);
    /* 見つからなければ ARP要求 */
    if (!cache) {
        debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
        /* Exercise15-1: ARP キャッシュに問い合わせのエントリを作成 */
        /* (1) 新しいエントリのスペースを確保 */
        /* - スペースを確保できなかったら ERROR を返す */
        cache = arp_cache_alloc();
        if (!cache) {
            mutex_unlock(&mutex);
            errorf("arp_cache_alloc() failure");
            return ARP_RESOLVE_ERROR;
        }
        /* (2) エントリの各フィールドに値を設定する */
        /* - state ･･･ INCOMPLETE */
        cache->state = ARP_CACHE_STATE_INCOMPLETE;
        /* - pa ･･･ 引数で受け取ったプロトコルアドレス */
        cache->pa = pa;
        /* - ha ･･･ 未設定 */
        /* - timestamp ･･･ 現在時刻(gettimeofday() で取得) */
        gettimeofday(&cache->timestamp, NULL);

        mutex_unlock(&mutex);
        /* ARP 要求の送信関数を呼び出す */
        arp_request(iface, pa);
        /* 問い合わせ中なので INCOMPLETE を返す */
        return ARP_RESOLVE_INCOMPLETE;
    }
    /* 見つかったエントリが INCOMPLETE のままだったらパケロスしているかもしれないので */
    /* 念のため再送する。タイムスタンプは更新しない。 */
    if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
        mutex_unlock(&mutex);
        arp_request(iface, pa); /* just in case packet loss */
        return ARP_RESOLVE_INCOMPLETE;
    }

    /* 見つかったハードウェアアドレスをコピー */
    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    debugf("resolved, pa=%s, ha=%s",
        ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    /* 見つかったので FOUND を返す */
    return ARP_RESOLVE_FOUND;
}

/**
 * ARP のタイマーハンドラ
 */
static void
arp_timer_handler(void)
{
    struct arp_cache *entry;
    struct timeval now, diff;

    /* ARP キャッシュへのアクセスを mutex で保護 */
    mutex_lock(&mutex);
    gettimeofday(&now, NULL); /* 現在時刻を取得 */
    for (entry = caches; entry < tailof(caches); entry++) { /* ARP キャッシュの配列を巡回 */
        /* 未使用のエントリと静的エントリは除外 */
        if (entry->state != ARP_CACHE_STATE_FREE && entry->state != ARP_CACHE_STATE_STATIC) {
            /* Exercise16-3: タイムアウトしたエントリの削除 */
            /* - エントリのタイムスタンプから現在までの経過時間を求める */
            timersub(&now, &entry->timestamp, &diff);
            /* - タイムアウト時間（ARP_CACHE_TIMEOUT）が経過していたらエントリを削除する */
            if (diff.tv_sec > ARP_CACHE_TIMEOUT) {
                arp_cache_delete(entry);
            }
        }
    }
    mutex_unlock(&mutex);
}

/**
 * ARP の初期化(登録)
 */
int
arp_init(void)
{
    /* ARP のタイマーハンドラを呼び出す際のインターバル */
    struct timeval interval = {1,0}; /* 1s */

    /* Exercise13-4: プロトコルスタックに ARP を登録する */
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    /* Exerice16-4: ARPのタイマハンドラーを登録 */
    if (net_timer_register(interval, arp_timer_handler) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    return 0;
}