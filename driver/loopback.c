/**
 * ループバックデバイス
*/

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define LOOPBACK_MTU UINT16_MAX /* maxmum size of IP datagram */
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE+1)

#define PRIV(x) ((struct loopback *)x->priv)

/**
 * ループバックデバイスのドライバ内で使用するプライベートなデータを格納するための構造体
*/
struct loopback {
    int irq;
    mutex_t mutex;
    struct queue_head queue;
};

/**
 * キューのエントリの構造体
 * - データ本体と付随する情報(メタデータ)を格納
 * - この構造体の最後のメンバは "フレキブル配列メンバ" と呼ばれる特殊なメンバ変数
 *      + 構造体の最後にだけ配置できるサイズ不明の配列
 *      + メンバ変数としてアクセスできるが構造体のサイズには含まれない (必ずデータ部分も含めてメモリを確保すること)
*/
struct loopback_queue_entry {
    uint16_t type;
    size_t len;
    uint8_t data[]; /* flexible array member */
};

/**
 * 送信関数
 * - 渡されたデータをキューに格納する
 * - 割り込みを発生させる
*/
static int
loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    struct loopback_queue_entry *entry;
    unsigned int num;

    /* キューへのアクセスを mutex で保護する(unlock を忘れずに) */
    mutex_lock(&PRIV(dev)->mutex);
    /* キューの上限を超えていたらエラーを返す */
    if (PRIV(dev)->queue.num >= LOOPBACK_QUEUE_LIMIT) {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("queue is full");
        return -1;
    }

    /* キューに格納するエントリのメモリを確保 */
    /* ※ 便利ツールのキューはポインタを保持するだけ */
    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry) {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("memory_alloc() failure");
        return -1;
    }
    /* メタデータの設定とデータ本体のコピー */
    entry->type = type;
    entry->len = len;
    memcpy(entry->data, data, len);
    /* エントリをキューへ格納 */
    queue_push(&PRIV(dev)->queue, entry);
    num = PRIV(dev)->queue.num;
    mutex_unlock(&PRIV(dev)->mutex);
    debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num, dev->name, type, len);
    debugdump(data, len);
    /* 割り込みを発生させる */
    intr_raise_irq(PRIV(dev)->irq);
    return 0;
}

/**
 * 割り込みハンドラ
 * - キューからデータを取り出す
 * - プロトコルスタックの入力ハンドラ (net_input_handler) を呼び出す
*/
static int
loopback_isr(unsigned int irq, void *id)
{
    struct net_device *dev;
    struct loopback_queue_entry *entry;

    dev = (struct net_device *)id;
    /* キューへのアクセスを mutex で保護 */
    mutex_lock(&PRIV(dev)->mutex);
    while (1) {
        /* キューからエントリを取り出す */
        entry = queue_pop(&PRIV(dev)->queue);
        if (!entry) {
            /* 取り出すエントリが無くなったらループを抜ける */
            break;
        }
        debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd", PRIV(dev)->queue.num, dev->name, entry->type, entry->len);
        debugdump(entry->data, entry->len);
        /* 受信データ本体と付随する情報を渡す */
        net_input_handler(entry->type, entry->data, entry->len, dev);
        /* エントリのメモリを解放する */
        memory_free(entry);
    }
    mutex_unlock(&PRIV(dev)->mutex);
    return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

/**
 * 初期化
 * - デバイスの生成と登録
 * - 割り込みハンドラの登録
*/
struct net_device *
loopback_init(void)
{
    struct net_device *dev;
    struct loopback *lo;

    /* Exercise 3-1: デバイスの生成とパラメータの設定 */
    dev = net_device_alloc();
    if (!dev) {
        errorf("net device alloc() failure");
        return NULL;
    }

    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;
    dev->ops = &loopback_ops;

    /* ドライバの中で使用するプライベートなデータの準備 */
    lo = memory_alloc(sizeof(*lo));
    if (!lo) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    lo->irq = LOOPBACK_IRQ;
    mutex_init(&lo->mutex);
    queue_init(&lo->queue);
    dev->priv = lo; /* プライベートなデータをデバイス構造体に格納する */

    /* Exercise 3-2: デバイスの登録と割り込みハンドラの設定 */
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        return NULL;
    }
    intr_request_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name, dev);

    debugf("initialized, dev=%s", dev->name);
    return dev;
}