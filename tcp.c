#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

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

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE          0
#define TCP_PCB_STATE_CLOSED        1
#define TCP_PCB_STATE_LISTEN        2
#define TCP_PCB_STATE_SYN_SENT      3
#define TCP_PCB_STATE_SYN_RECEIVED  4
#define TCP_PCB_STATE_ESTABLISHED   5
#define TCP_PCB_STATE_FIN_WAIT1     6
#define TCP_PCB_STATE_FIN_WAIT2     7
#define TCP_PCB_STATE_CLOSING       8
#define TCP_PCB_STATE_TIME_WAIT     9
#define TCP_PCB_STATE_CLOSE_WAIT   10
#define TCP_PCB_STATE_LAST_ACK     11

/* TCP 疑似ヘッダ構造体(チェックサム計算時に使用する) */
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

/**
 * 受信したTCPセグメントから重要な情報を抽出した構造体
 * （RFCの記述に合わせてある）
 */
struct tcp_segment_info {
    /* シーケンス番号 */
    uint32_t seq;
    /* 確認応答番号 */
    uint32_t ack;
    /* シーケンス番号を消費するデータ長 (SYN と FIN フラグも 1 とカウントする) */
    uint16_t len;
    /* 受信ウィンドウ (相手の受信バッファの空き情報) */
    uint16_t wnd;
    /* 緊急ポインタ（いまのところ使用しない） */
    uint16_t up;
};

/**
 * コントロールブロック構造体
 */
struct tcp_pcb {
    /* コネクションの状態 */
    int state;
    /* コネクションの両端のアドレス情報 */
    struct ip_endpoint local;
    struct ip_endpoint foreign;
    /* 送信時に必要となる情報 */
    struct {
        /* 次に送信するシーケンス番号 */
        uint32_t nxt;
        /* ACKが返ってきていない最後のシーケンス番号 */
        uint32_t una;
        /* 相手の受信ウィンドウ（受信バッファの空き状況） */
        uint16_t wnd;
        /* 緊急ポインタ（未使用） */
        uint16_t up;
        /* snd.wnd を更新した時の受信セグメントのシーケンス番号 */
        uint32_t wl1;
        /* snd.wnd を更新した時の受信セグメントのACK番号 */
        uint32_t wl2;
    } snd;
    /* 自分の初期シーケンス番号 */
    uint32_t iss;
    /* 受信時に必要となる情報 */
    struct {
        /* 次に受信を期待するシーケンス番号（ACKで使われる） */
        uint32_t nxt;
        /* 自分の受信ウィンドウ（受信バッファの空き状況） */
        uint16_t wnd;
        /* 緊急ポインタ（未使用） */
        uint16_t up;
    } rcv;
    /* 相手の初期シーケンス番号 */
    uint32_t irs;
    /* 送信デバイスのMTU */
    uint16_t mtu;
    /* 最大セグメントサイズ */
    uint16_t mss;
    /* receive buffer */
    uint8_t buf[65535];
    struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

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
 * TCP Protocol Control Block (PCB)
 * 
 * NOTE: TCP PCB functions must be called after mutex locked
 */

/**
 * コントロールブロックの領域確保
 * @return コントロールブロックの構造体のポインタ
 */
static struct tcp_pcb *
tcp_pcb_alloc(void)
{
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        /* FREE 状態の PCB を見つけて返す */
        if (pcb->state == TCP_PCB_STATE_FREE) {
            /* CLOSED 状態に初期化する */
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

/**
 * コントロールブロックの解放
 * @param [in,out] pcb コントロールブロック構造体ポインタ
 */
static void
tcp_pcb_release(struct tcp_pcb *pcb)
{
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* PCB 利用しているタスクがいたらこのタイミングでは解放できない */
    /* タスクを起床させてる（他のタスクに解放を任せる） */
    if (sched_ctx_destroy(&pcb->ctx) == 1) {
        sched_wakeup(&pcb->ctx);
        return;
    }
     debugf("released, local=%s, foreign=%s",
        ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
        ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb)); /* pcb->state is set to TCP_PCB_STATE_FREE (0) */

}

/**
 * コントロールブロックの検索（select）
 * @param [in] local ローカルアドレス
 * @param [in] foreign 外部アドレス
 * @return コントロールブロック構造体ポインタ
 */
static struct tcp_pcb *
tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port) {
            /* ローカルアドレスに bind 可能かどうか調べるときは外部アドレスを指定せずに呼ばれる */
            /* ローカルアドレスがマッチしているので返す */
            if (!foreign) {
                return pcb;
            }
            /* ローカルアドレスと外部アドレスが共にマッチ */
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) {
                return pcb;
            }
            /* 外部アドレスを指定せずに LISTEN していたらどんな外部アドレスでもマッチする */
            /* ローカルアドレス/外部アドレス共にマッチしたものが優先されるのですぐには返さない */
            if (pcb->state == TCP_PCB_STATE_LISTEN) {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) {
                    /* LISTEND with wildcard foreign address/port */
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

/**
 * コントロールブロックの検索 (get)
 * @param [in] id ID（pcbsのインデックス)
 * @return コントロールブロック構造体ポインタ
 */
static struct tcp_pcb *
tcp_pcb_get(int id)
{
    struct tcp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs)) {
        /* out of range */
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state == TCP_PCB_STATE_FREE) {
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
tcp_pcb_id(struct tcp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

/**
 * TCP セグメントの送信
 * @param [in] seq
 * @param [in] ack
 * @param [in] flg
 * @param [in] wnd
 * @param [in,out] data
 * @param [in] len
 * @param [in,out] local
 * @param [in,out] foreign
 */
static ssize_t
tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *)buf;

    /* Exercise23-1: TCP セグメントの生成 */
    hdr = (struct tcp_hdr *)buf;
    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    memcpy(hdr + 1, data, len);
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    total = sizeof(*hdr) + len;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)",
        ip_endpoint_ntop(local, ep1, sizeof(ep1)),
        ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
        total, len);

    /* Exercise23-2: IP の送信関数を呼び出す */
    tcp_dump((uint8_t *)hdr, total);
    if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1) {
        return -1;
    }

    return len;
}

/**
 * TCP の送信関数
 * @param [in,out] pcb
 * @param [in] flg
 * @param [in,out] data
 * @param [in] len
 * @return
 */
static ssize_t
tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
    uint32_t seq;

    seq = pcb->snd.nxt;
    /* SYN フラグが指定されるのは初回送信時なので iss (初期送信シーケンス番号)を使う */
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN)) {
        seq = pcb->iss;
    }

    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
        /* TODO: add retransmission queue */
    }
    /* PCB の情報を使って TCP セグメントを送信 */
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

/**
 * 到着セグメントの処理
 */
/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb;

    pcb = tcp_pcb_select(local, foreign);
    /* 使用していないポート宛に届いた TCP セグメントの処理 */
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            /* RST フラグを含むセグメントは無視 */
            return;
        }
        /* ACK フラグを含まないセグメントを受信･･･こちらからは何も送信していないと思われる状況（何か送っていればACKを含んだセグメントを受信するはず */
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            /* 相手が送ってきたデータへの ACK 番号 (seq->seq + seq->len) を設定して RST を送信 */
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        }
        /* ACK フラグを含むセグメントを受信･･･こちらから何か送信していると思われる状況（何か送っているので ACK を含んだセグメントを受信している */
        /* ※ 以前に存在していたコネクションのセグメントが遅れて到着？ */
        else {
            /* 相手から伝えられた ACK 番号 (相手が次に欲しがっているシーケンス番号) をシーケンス番号に設定して RST を送信 */
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }
    /* implemented in the next step */

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
    struct ip_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;

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

    /* struct ip_endpoint の変数に入れなおす */
    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    /* tcp_segment_arrives() で必要な情報 (SEG.XXX) を集める */
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
        seg.len++; /* SYN flag consumes one sequence number */
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        seg.len++; /* FIN flag consumes one sequence number */
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);

    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);

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