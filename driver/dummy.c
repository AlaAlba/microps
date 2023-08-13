#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX /* maximum size of IP datagram */

#define DUMMY_IRQ INTR_IRQ_BASE

static int
dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    /* drop data */
    /* テスト用に割り込みを発生させる */
    intr_raise_irq(DUMMY_IRQ);
    return 0;
}

static int
dummy_isr(unsigned int irq, void *id)
{
    /* 呼び出されたことが分かればいいのでデバッグ出力のみ */
    debugf("irq=%u, dev=%s", irq, ((struct net_device *)id)->name);
    return 0;
}

/* デバイスドライバが実装している関数へのポインタ */
static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit, /* 送信関数のみ設定 */
};

struct net_device *
dummy_init(void)
{
    struct net_device *dev;

    /* デバイスを生成 */
    dev = net_device_alloc();
    if (!dev) {
        errorf("net device alloc() failure");
        return NULL;
    }

    dev->type = NET_DEVICE_TYPE_DUMMY;
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /* non address */
    dev->ops = &dummy_ops;
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        return NULL;
    }
    
    /* 割り込みハンドラとして dummy_isr を登録する */
    intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);
    
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
