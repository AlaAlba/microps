#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

/**
 * プロトコル構造体
 * - 連結リスト
*/
struct net_protocol {
    /* 次のプロトコルへのポインタ */
    struct net_protocol *next;
    
    /* プロトコルの種別 (NET_PROTOCOL_TYPE_XXX) */
    uint16_t type;

    /* 受信キュー */
    struct queue_head queue; /* input queue */

    /* プロトコルの入力関数へのポインタ */
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

/**
 * 受信キューのエントリの構造体
 * - 受信データと付随する情報（メタデータ）を格納
*/
struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
    uint8_t data[];
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
/* デバイスリスト(リストの先頭を指すポインタ) */
static struct net_device *devices;
/* 登録されているプロトコルのリスト */
static struct net_protocol *protocols;

/**
 * デバイスの生成
*/
struct net_device *
net_device_alloc(void)
{
    struct net_device *dev;

    /* デバイス構造体のサイズのメモリを確保 */
    dev = memory_alloc(sizeof(*dev));
    if (!dev) {
        /* メモリが確保できなかったらエラーとしてNULLを返す */
        errorf("memory_alloc() failure");
        return NULL;
    }
    return dev;
}

/* NOTE: must not be call after net_run() */
int
net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;

    /* デバイスのインデックス番号を指定 */
    dev->index = index++;
    /* デバイス名生成 */
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);

    /* デバイスリストの先頭に追加 */
    dev->next = devices;
    devices = dev;

    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;

}

/**
 * デバイスのオープン
*/
static int
net_device_open(struct net_device *dev)
{
    /* デバイスの状態を確認(既にUP状態の場合はエラーを返す) */
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }

    /* デバイスドライバのオープン関数を呼び出す */
    if (dev->ops->open) {
        /* エラーが返されたらエラーを返す */
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    /* UPフラグを立てる */
    dev->flags |= NET_DEVICE_FLAG_UP;

    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/**
 * デバイスのクローズ
*/
static int
net_device_close(struct net_device *dev)
{
    /* デバイスの状態を確認し、UP状態でなければエラーを返す */
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    /* デバイスドライバのクローズ関数を呼び出す */
    if (dev->ops->close) {
        /* エラーが返されたらエラーを返す */
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    /* UPフラグを落とす */
    dev->flags &= ~NET_DEVICE_FLAG_UP;

    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/**
 * デバイスとインターフェースの紐づけ
*/
/* NOTE: must not be call after net_run() */
int
net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    struct net_iface *entry;

    /* 重複登録のチェック */
    /* - 単純化のために1つのデバイスに対して同じ family のインターフェースを複数登録できないように制限している */
    /* - 登録しようとしているインターフェースと同じ family のインターフェースが既に存在していたらエラーを返す */
    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == iface->family) {
            /* NOTE: For simplicity, only one iface can be added per family. */
            errorf("already exists, dev=%s, family=%d", dev->name, entry->family);
            return -1;
        }
    }
    iface->dev = dev;

    /* Exercise7-1: デバイスのインターフェースリストの先頭に iface を挿入 */
    iface->next = dev->ifaces; /* 次の iface は今の先頭 */
    dev->ifaces = iface; /* ifaces の先頭に追加 */

    return 0;
}

/**
 * デバイスに紐づくIPインターフェースの取得
*/
struct net_iface *
net_device_get_iface(struct net_device *dev, int family)
{
    /* Exercise7-2: デバイスに紐づくインターフェースを検索          */
    struct net_iface *entry;

    /* - デバイスのインターフェースリスト (dev->ifaces) を巡回 */
    for (entry = dev->ifaces; entry; entry = entry->next) {
        /* family が一致するインターフェースを返す */
        if (entry->family == family) {
            break;
        }
    }
    /* ※合致するインターフェースを発見できなかったら NULL を返す */
    return entry;
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    /* デバイス状態を確認し、UP状態でなければ送信できないのでエラーを返す */
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    /* デバイスのMTUを超えるサイズのデータは送信できないのでエラーを返す */
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    /* デバイスドライバの出力関数を呼び出す */
    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        /* エラーが返されたらエラーを返す */
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

/**
 * プロトコルの登録
*/
/* NOTE: must not be call after net_run() */
int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;

    /* 重複登録の確認 (指定された種別のプロトコルが登録済みの場合はエラーを返す) */
    for (proto = protocols; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }

    /* プロトコル構造体のメモリを確保 */
    proto = memory_alloc(sizeof(*proto));
    if (!proto) {
        errorf("memory_alloc() failure");
        return -1;
    }
    /* プロトコル種別と入力関数を指定 */
    proto->type = type;
    proto->handler = handler;
    /* プロトコルリストの先頭に追加 */
    proto->next = protocols;
    protocols = proto;
    infof("registered, type=0x%04x", type);
    return 0;
}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    /* 到着データの振り分けと受信キューへの挿入 */
    
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            /* Exercise 4-1: プロトコルの受信キューにエントリを挿入 */
            /* (1) 新しいエントリのメモリを確保 (失敗したらエラーを返す) */
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry) {
                errorf("memory_alloc() failure");
                return -1;
            }
            /* (2) 新しいエントリへメタデータの設定と受信データのコピー */
            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);
            /* (3) キューに新しいエントリを挿入 (失敗したらエラーを返す) */
            if (!queue_push(&proto->queue, entry)) {
                errorf("queue_push() failure");
                memory_free(entry);
                return -1;
            }

            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
                proto->queue.num, dev->name, type, len);
            debugdump(data, len);

            /* プロトコルの受信キューへエントリを追加した後、ソフトウェア割り込みを発生させる */
            intr_raise_irq(INTR_IRQ_SOFTIRQ);

            return 0;
        }
    }

    /* プロトコルが見つからなかったら黙って捨てる */
    return 0;
}

int
net_run(void)
{
    struct net_device *dev;

    /* 割り込み機構の起動 */
    if (intr_run() == -1) {
        errorf("intr_run() failure");
        return -1;
    }

    debugf("open all devices...");
    /* 登録済みの全デバイスをオープン */
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("running...");
    return 0;
}

int
net_softirq_handler(void)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    /* プロトコルリストを巡回 (全てのプロトコルを確認) */
    for (proto = protocols; proto; proto = proto->next) {
        while (1) {
            /* 受信キューからエントリを取り出す (エントリが存在する間処理を繰り返す) */
            entry = queue_pop(&proto->queue);
            if (!entry) {
                break;
            }
            debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zu",
                proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);
            /* プロトコルの入力関数を呼び出す */
            proto->handler(entry->data, entry->len, entry->dev);
            /* 使い終わったエントリのメモリを開放 */
            memory_free(entry);
        }
    }
    return 0;
}

void
net_shutdown(void)
{
    struct net_device *dev;

    debugf("close all devices...");
    /* 登録済みの全デバイスをクローズ */
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }

    /* 割り込み機構の終了 */
    intr_shutdown();

    debugf("shutting down");
}

int
net_init(void)
{
    /* 割り込み機構の初期化 */
    if (intr_init() == -1) {
        errorf("intr_init() failure");
        return -1;
    }

    /* IPの初期化 */
    if (ip_init() == -1) {
        errorf("ip_init() failure");
        return -1;
    }

    infof("initialized");
    return 0;
}
