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

struct loopback {
    int irq;
    mutex_t mutex;
    struct queue_head queue;
};

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
}

/**
 * 割り込みハンドラ
 * - キューからデータを取り出す
 * - プロトコルスタックの入力ハンドラ (net_input_handler) を呼び出す
*/
static int
loopback_isr(unsigned int irq, void *id)
{
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
}