#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"

/* Protocol Control Block (PCB) のサイズ */
#define UDP_PCB_SIZE 16

/* Protocol Control Block (PCB) の状態を示す定数 */
#define UDP_PCB_STATE_FREE      0
#define UDP_PCB_STATE_OPEN      1
#define UDP_PCB_STATE_CLOSING   2

/**
 * 疑似ヘッダの構造体（チェックサム計算時に使用する）
 */
struct pseudo_hdr {
    /* Source Address */
    uint32_t src;
    /* Destination Address */
    uint32_t dst;
    /* Zero */
    uint8_t zero;
    /* Protocol */
    uint8_t protocol;
    /* UDP Length */
    uint16_t len;
};

/**
 * UDPヘッダの構造体
 */
struct udp_hdr {
    /* Source Port */
    uint16_t src;
    /* Destination Port */
    uint16_t dst;
    /* Length */
    uint16_t len;
    /* Checksum */
    uint16_t sum;
};

/**
 * コントロールブロックの構造体
 */
struct udp_pcb {
    /* 状態 */
    int state;
    /* 自分のアドレス＆ポート番号 */
    struct ip_endpoint local;
    struct queue_head queue; /* receive queue */
};

/**
 * 受信キューのエントリの構造体
 */
struct udp_queue_entry {
    /* 送信元のアドレス＆ポート番号 */
    struct ip_endpoint foreign;
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
/* コントロールブロックの配列 */
static struct udp_pcb pcbs[UDP_PCB_SIZE];

/**
 * デバッグ出力
 * @param [in,out] data UDPデータ
 * @param [in] len UDP長
 */
static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * UDP Protocol Control Block (PCB)
 * 
 * NOTE: UDP PCB functions must be called after mutex locked
 */

/**
 * コントロールブロックの領域確保
 * @return コントロールブロックの構造体のポインタ
 */
static struct udp_pcb *
udp_pcb_alloc(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        /* 使用されていないPCBを探して返す */
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            return pcb;
        }
        /* 空きがなければ NULL を返す */
        return NULL;
    }
}

/**
 * コントロールブロックの解放
 * @param [in,out] pcb コントロールブロック構造体ポインタ
 */
static void
udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    /* 値をクリア */
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;

    while (1) { /* Discard the entries in the queue. */
        /* 受信キューを空にする */
        entry = queue_pop(&pcb->queue);
        if (!entry) {
            break;
        }
        memory_free(entry);
    }
}

/**
 * コントロールブロックの検索（select）
 * @param [in] addr IPアドレス
 * @param [in] port ポート番号
 * @return コントロールブロック構造体ポインタ
 */
static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        /* OPEN状態のPCBのみが対象 */
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            /* IPアドレスとポート番号が一致するPCBを探して返す */
            /* IPアドレスがワイルドカード(IP_ADDR_ANY) の場合、全てのアドレスに対して一致の判定を下す */
            if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port) {
                return pcb;
            }
        }
    }
    return NULL;
}

/**
 * コントロールブロックの検索 (get)
 * @param [in] id ID（pcbsのインデックス)
 * @return コントロールブロック構造体ポインタ
 */
static struct udp_pcb *
udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    /* 配列の範囲チェック (idをそのまま配列のインデックスとして使う) */
    if (id < 0 || id >= (int)countof(pcbs)) {
        /* out of range */
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) {
        /* OPEN状態でなければ NULL を返す */
        return NULL;
    }
    return pcb;
}

/**
 * コントロールブロックのインデックス取得
 * @param [in,out] pcb コントロールブロック構造体ポインタ
 * @return インデックス
 */
static int
udp_pcb_id(struct udp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

/**
 * UDPデータグラムの入力
 * @param [in,out] data
 * @param [in] len データサイズ
 * @param [in] src
 * @param [in] dst
 * @param [in,out] iface
 */
static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

    /* ヘッダサイズに満たないデータはエラーとする */
    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct udp_hdr *)data;
    /* IPから渡されたデータ長(len)とUDPヘッダに含まれるデータグラム長(hdr->len)が一致しない場合はエラー */
    if (len != ntoh16(hdr->len)) { /* just to make sure */
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    /* チェックサム計算のために疑似ヘッダを準備 */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    /* 疑似ヘッダ部分のチェックサムを計算（計算結果はビット反転されているので戻しておく） */
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    /* cksum16() の第3引数に psum を渡すことで続きを計算する */
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    udp_dump(data, len);

    /* PCBへのアクセスをミューテックスで保護 */
    mutex_lock(&mutex);
    /* 宛先アドレスとポート番号に対応するPCBを検索 */
    pcb = udp_pcb_select(dst, hdr->dst);
    /* PCB が見つからなければ中断 (ポートを使用しているアプリケーションが存在しない) */
    if (!pcb) {
        /* port is not in use */
        mutex_unlock(&mutex);
        return;
    }
    /* Exercise19-1: 受信キューへデータを格納 */
    /* (1) 受信キューのエントリのメモリを確保 */
    entry = memory_alloc(sizeof(*entry));
    /* (2) エントリの各項目に値を設定し、データをコピー */
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry->data, hdr+1, entry->len);
    /* (3) PCBの受信キューにエントリをプッシュ */
    if (!queue_push(&pcb->queue, entry)) {
        mutex_unlock(&mutex);
        errorf("queue_push() failure");
        return;
    }

    debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
    mutex_unlock(&mutex);
}

/**
 * UDPデータグラムの出力
 * @param [in,out] src
 * @param [in,out] dst
 * @param [in,out] data
 * @param [in] len
 * @return
 */
ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* IP のペイロードに載せきれないほど大きなデータが渡されたらエラーを返す */
    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
        errorf("too long");
        return -1;
    }
    hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    total = sizeof(*hdr) + len;
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);
    pseudo.src = src->addr;
    pseudo.dst =  dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    /* UDPデータグラムの生成 */
    /* - チェックサムの計算には疑似ヘッダを含める */

    debugf("%s => %s, len=%zu (payload=%zu)",
        ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);

    /* IPの送信関数を呼び出す */
    if (ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1) {
        errorf("ip_output() failure");
        return -1;
    }

    return len;
}

/**
 * UDPの初期化(登録)
 */
int
udp_init(void)
{
    /* Exercise18-3: IPの上位プロトコルとしてUDPを登録する */
    if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}

/**
 * UDP User Commands
 */

/**
 * UDP のオープン
 */
int
udp_open(void)
{
    struct udp_pcb *pcb;
    int id;
    /* Exercise19-2: UDPソケットのオープン */
    /* 新しくPCBを割り当てる */
    mutex_lock(&mutex);
    pcb = udp_pcb_alloc();
    if (!pcb) {
        errorf("udp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    /* PCBのIDを取得して返す */
    id = udp_pcb_id(pcb);
    mutex_unlock(&mutex);
    return id;
}

/**
 * UDP のクローズ
 */
int udp_close(int id)
{
    struct udp_pcb *pcb;
    /* Exercise19-3: UDPソケットのクローズ */
    /* IDからPCBのポインタを取得 */
    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    /* PCBを解放して 0 を返す */
    udp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

/**
 * ソケットとアドレスを紐づける（使うアドレスとポートを設定する）
 * @param [in] id
 * @param [in,out] local IPエンドポイント
 * @return 
 */
int
udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    /* Exercise 19-4: UDPソケットへアドレスとポート番号を紐づけ */
    /* (1) IDからPCBのポインタを取得 */
    pcb = udp_pcb_get(id);
    /* 　・失敗したらエラー（-1）を返す */
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    /* (2) 引数 local で指定されたIPアドレスとポート番号をキーにPCBを検索 */
    exist = udp_pcb_select(local->addr, local->port);
    /* 　・PCBが見つかったらエラーを返す（そのアドレスとポート番号の組み合わせは既に使用されている）※ mutexのアンロックを忘れずに */
    if (exist) {
        errorf("already used, id=%d, exist=%s", id, ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }
    /* (3) pcb->local に local の値をコピー */
    pcb->local = *local;

    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}