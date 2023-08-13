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
