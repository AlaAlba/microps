#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

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
/**
 * TCP FLG の特定のフラグが設定されているかどうかを判別する
 * @param [in] x 対象のTCP FLAG Byte
 * @param [out] y 比較対象のフラグ
 * @return 設定(1), 設定されていない(0)
*/
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


/* TCP ヘッダ構造体 */
struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
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
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
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
 * @param [in,out] seg 受信したTCPセグメントから重要な情報を抽出した構造体
 * @param [in] flags TCPヘッダフラグ
 * @param [in,out] data データ
 * @param [in] len データ長
 * @param [in,out] local ローカルアドレス
 * @param [in,out] foreign 外部アドレス
 */
/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    int acceptable = 0;
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

    switch (pcb->state) {
    case TCP_PCB_STATE_LISTEN:
        /**
         * 1st check for an RST
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            /* 無視 */
            return;
        }

        /**
         * 2nd check for an ACK
         */
        /* ACK フラグを含んでいたら RST を送信 */
        /* 相手が次に期待しているシーケンス番号 (seg->ack) を設定 */
        if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
        }

        /**
         * 3rd check for an SYN
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
            /* ignore: security/compartment check */
            /* ignore: precedence check */

            /* 両端の具体的なアドレスが確定する */
            pcb->local = *local;
            pcb->foreign = *foreign;
            /* 受信ウィンドウのサイズを設定 */
            pcb->rcv.wnd = sizeof(pcb->buf);
            /* 次に受信を期待するシーケンス番号（ACKで使われる） */
            pcb->rcv.nxt = seg->seq + 1;
            /* 初期受信シーケンス番号の保存 */
            pcb->irs = seg->seq;
            /* 初期送信シーケンス番号の採番 */
            pcb->iss = random();
            /* SYN+ACK の送信 */
            tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
            /* 次に送信するシーケンス番号 */
            pcb->snd.nxt = pcb->iss + 1;
            /* ACK が返ってきていない最後のシーケンス番号 */
            pcb->snd.una = pcb->iss;
            /* SYN_RECEIVED へ移行 */
            pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
            /* ignore: Note that any other incoming control or data             */
            /* (combined with SYN) will be processed in the SYN-RECEIVED state, */
            /* but processing of SYN and ACK  should not be repeated            */
            return;
        }

        /**
         * 4th other text or control
         */

        /* drop segment */

        return;
    
    case TCP_PCB_STATE_SYN_SENT:
        /**
         * 1st check the ACK bit
         */

        /**
         * 2nd check the RST bit
         */

        /**
         * 3rd check security and precedence (ignore)
         */

        /**
         * 4th check the SYN bit
         */

        /**
         * 5th, if neither of the SYN or RST bits is set then drop the segment and return
         */

        /* drop segment */
        
        return;
    }

    /**
     * Otherwise
     */

    /**
     * 1st check sequence number
     */
    switch (pcb->state) {
    case TCP_PCB_STATE_SYN_RECEIVED:
    case TCP_PCB_STATE_ESTABLISHED:
        /* 受信セグメントにデータが含めれているかどうか */
        if (!seg->len) {
            /* 受信バッファに空きがあるかどうか */
            if (!pcb->rcv.wnd) {
                /* 次に期待しているシーケンス番号と一致するかどうか */
                if (seg->seq == pcb->rcv.nxt) {
                    acceptable = 1;
                }
            } else {
                if (pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) {
                    /* 次に期待するシーケンス番号以上で、ウィンドウの範囲内なら受け入れる */
                    acceptable = 1;
                }
            }
        } else {
            /* 受信バッファに空きがあるかどうか */
            if (!pcb->rcv.wnd) {
                /* not acceptable */
            } else {
                /* 次に期待するシーケンス番号以上で、データの開始位置がウィンドウの範囲内なら受け入れる */
                /* もしくは、受信済みと新しいデータの両方を含むセグメントで、新しいデータがウィンドウの範囲内なら受け入れる */
                if ((pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) ||
                    (pcb->rcv.nxt <= seg->seq + seg->len - 1 && seg->seq + seg->len -1 < pcb->rcv.nxt + pcb->rcv.wnd)) {
                        acceptable = 1;
                }
            }
        }
        
        if (!acceptable) {
            if (!TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            }
            return;
        }

        /*
         * In the following it is assumed that the segment is the idealized
         * segment that begins at RCV.NXT and does not exceed the window.
         * One could tailor actual segments to fit this assumption by
         * trimming off any portions that lie outside the window (including
         * SYN and FIN), and only processing further if the segment then
         * begins at RCV.NXT.  Segments with higher begining sequence
         * numbers may be held for later processing.
         */

    }

    /**
     * 2nd check the RST bit
     */

    /**
     * 3rd check security and precedence (ignore)
     */

    /**
     * 4th check the SYN bit
     */

    /**
     * 5th check the ACK field
     */
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
        /* drop segment */
        /* ACK フラグを含んでいないセグメントは破棄 */
        return;
    }
    switch (pcb->state) {
    case TCP_PCB_STATE_SYN_RECEIVED:
        /* 送信セグメントに対する妥当な ACK かどうかの判断 */
        if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) {
            /* ESTABLISHED の状態に移行 (コネクション確立) */
            pcb->state = TCP_PCB_STATE_ESTABLISHED;
            /* PCB の状態が変化を待っているスレッドを起床 */
            sched_wakeup(&pcb->ctx);
        } else {
            /* RST フラグを含んだセグメントを送信 */
            /* 相手が次に期待しているシーケンス番号（seg->ack）を設定 */
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
        }
        /* fall through */
    case TCP_PCB_STATE_ESTABLISHED:
        /* まだ ACK を受け取っていない送信データに対する ACK かどうか */
        if (pcb->snd.una < seg->ack && seg->ack <= pcb->snd.nxt) {
            /* 確認が取れているシーケンス番号の値を更新 */
            pcb->snd.una = seg->ack;
            /* TODO: Any segments on the retransmission queue which are thereby entirely acknowledged are removed */
            /* ignore: Users should receive positive acknowledgments for buffers
                        which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with "ok" response) */
            /* 最後にウィンドウの情報を更新したときよりも後に送信されたセグメントかどうか */
            if (pcb->snd.wl1 < seg->seq || (pcb->snd.wl1 == seg->seq && pcb->snd.wl2 <= seg->ack)) {
                /* ウィンドウの情報を更新 */
                pcb->snd.wnd = seg->wnd;
                pcb->snd.wl1 = seg->seq;
                pcb->snd.wl2 = seg->ack;
            }
        } else if (seg->ack < pcb->snd.una) {
            /* 既に確認済みの範囲に対する ACK */
            /* ignore */
        } else if (seg->ack > pcb->snd.nxt) {
            /* 範囲外 (まだ送信していないシーケンス番号）への ACK */
            tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            return;
        }
        break;

    }

    /**
     * 6th, check the URG bit (ignore)
     */

    /**
     * 7th, process the segment text
     */
    switch (pcb->state) {
    case TCP_PCB_STATE_ESTABLISHED:
        if (len) {
            /* 受信データをバッファにコピーして ACK を返す */
            memcpy(pcb->buf + (sizeof(pcb->buf) - pcb->rcv.wnd), data, len);
            /* 次に期待するシーケンス番号を更新 */
            pcb->rcv.nxt = seg->seq + seg->len;
            /* データを格納した分だけウィンドウサイズを小さくする */
            pcb->rcv.wnd -= len;
            /* 確認応答(ACK) を送信 */
            tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            sched_wakeup(&pcb->ctx);
        }
        break;
    }

    /**
     * 8th, check the FIN bit
     */

    return;

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

static void
event_handler(void *arg)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state != TCP_PCB_STATE_FREE) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
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
    net_event_subscribe(event_handler, NULL);
    return 0;
}

/**
 * TCP User Command (RFC793)
 */

int
tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active)
{
    struct tcp_pcb *pcb;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb) {
        errorf("tcp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    /* TODO: 能動的なオープンはまだ実装していない */
    if (active) {
        errorf("active open does not implement");
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    } else {
        debugf("passive open: local=%s, waiting for connection...", ip_endpoint_ntop(local, ep1, sizeof(ep1)));
        pcb->local = *local;
        /* RFC793の仕様だと外部アドレスを限定して LISTEN 可能 (ソケットAPIではできない) */
        if (foreign) {
            pcb->foreign = *foreign;
        }
        /* LISTEN 状態へ移行 */
        pcb->state = TCP_PCB_STATE_LISTEN;
    }
AGAIN:
    state = pcb->state;
    /* waiting for state changed */
    /* PCB の状態が変化したらループを抜ける */
    while (pcb->state == state) {
        /* タスクを休止 */
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            /* シグナルによる割り込みが発生(EINTR) */
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }
    /* コネクション確立状態(ESTABLISED) かどうかの確認 */
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        /* SYN_RECEIVED の状態だったらリトライ */
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        /* PCB を CLOSED の状態にしてリリース */
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    id = tcp_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s",
        ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    pthread_mutex_unlock(&mutex);
    /* コネクションが確立したら PCB の ID を返す */
    return id;
}

int
tcp_close(int id)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    /* TODO: 暫定措置として RST を送信してコネクションを破棄 */
    tcp_output(pcb, TCP_FLG_RST, NULL, 0);
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

/**
 * データの送信
 * @param [in] id ID（pcbsのインデックス)
 * @param [in,out] data 送信するデータ
 * @param [in] len データ長
 * @return 送信済みのバイト数
 */
ssize_t
tcp_send(int id, uint8_t *data, size_t len)
{
    struct tcp_pcb *pcb;
    ssize_t sent = 0;
    struct ip_iface *iface;
    size_t mss, cap, slen;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_ESTABLISHED:
        /* 送信に使われるインターフェースを取得 */
        iface = ip_route_get_iface(pcb->foreign.addr);
        if (!iface) {
            errorf("iface not found");
            mutex_unlock(&mutex);
            return -1;
        }
        /* MSS (Max Segment Size) を計算 */
        mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
        /* 全て送信しきるまでループ */
        while (sent < (ssize_t)len) {
            /* 相手の受信バッファの状況を予測 */
            cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
            /* 相手の受信バッファが埋まっていたら空くまで待つ */
            if (!cap) {
                if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                    debugf("interrupted");
                    /* まだ何も送信していない状態でユーザー割り込みにより処理を中断 */
                    if (!sent) {
                        mutex_unlock(&mutex);
                        errno = EINTR;
                        return -1;
                    }
                    /* 1byteでも送信済みの場合(戻り値で送信済みのバイト数を返す必要あり) */
                    break;
                }
                /* 状態が変わっている可能性もあるので状態の確認から再試行 */
                goto RETRY;
            }
            /* MSS のサイズで分割して送信 */
            slen = MIN(MIN(mss, len - sent), cap);
            /* ACK フラグを含める。 PSH フラグは飾り程度の扱い */
            if (tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_PSH, data + sent, slen) == -1) {
                errorf("tcp_output() failure");
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp_pcb_release(pcb);
                mutex_unlock(&mutex);
                return -1;
            }
            /* 次に送信するシーケンス番号を更新 */
            pcb->snd.nxt += slen;
            /* 送信済みバイト数を更新 */
            sent += slen;
        }
        break;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    mutex_unlock(&mutex);
    return sent;

}

/**
 * データの受信
 * @param [in] id ID（pcbsのインデックス)
 * @param [in,out] buf バッファ
 * @param [in] size バッファサイズ
 * @return 受信データサイズ
 */
ssize_t
tcp_receive(int id, uint8_t *buf, size_t size)
{
    struct tcp_pcb *pcb;
    size_t remain, len;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_ESTABLISHED:
        remain = sizeof(pcb->buf) - pcb->rcv.wnd;
        /* 受信バッファにデータが存在しない場合はタスクを休止 */
        if (!remain) {
            if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                /* まだ何も受信していない状態でユーザ割り込みにより処理を中断 */
                debugf("interrupted");
                mutex_unlock(&mutex);
                errno = EINTR;
                return -1;
            }
            /* 状態が変わっている可能性もあるため状態確認から再試行 */
            goto RETRY;
        }
        break;
    
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    /* buf に収まる分だけコピー */
    len = MIN(size, remain);
    memcpy(buf, pcb->buf, len);
    /* コピー済みのデータを受信バッファから消す */
    memmove(pcb->buf, pcb->buf + len, remain - len);
    pcb->rcv.wnd += len;
    mutex_unlock(&mutex);
    return len;
}