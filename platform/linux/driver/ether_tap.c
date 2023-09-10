#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE+2)

/**
 * タップデバイス
 */
struct ether_tap {
    /* TAPデバイス名 */
    char name[IFNAMSIZ];
    /* ファイルディスクリプタ */
    int fd;
    /* IRQ番号 */
    unsigned int irq;
};

/* デバイス構造体からプライベートデータを取得して ether_tap にキャスト */
#define PRIV(x) ((struct ether_tap *)x->priv)

/**
 * Ethernet デバイス (TAP) HW アドレスの取得
 * @param [in,out] dev デバイス構造体ポインタ
 * @return 結果
 */
static int
ether_tap_addr(struct net_device *dev)
{
    int soc;
    struct ifreq ifr = {}; /* ioctl() で使うリクエスト/レスポンス兼用の構造体 */

    /* ioctl() の SIOCGIFHWADDR 要求がソケットとして開かれたディスクリプタのみで有効なため、 */
    /* 通信するわけではないが、ソケットをオープンする必要がある。 */

    /* なんでもいいのでソケットをオープンする */
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }
    /* ハードウェアアドレスを取得したいデバイスの名前を設定する */
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
    /* ハードウェアアドレスの取得を要求する */
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }
    /* 取得したアドレスをデバイス構造体にコピー */
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    /* 使い終わったソケットをクローズ */
    close(soc);
    return 0;
}

/**
 * Ethernet デバイス (TAP) オープン
 * @param [in,out] dev デバイス構造体ポインタ
 * @return
 */
static int
ether_tap_open(struct net_device *dev)
{
    struct ether_tap *tap;
    struct ifreq ifr = {}; /* ioctl()で使うリクエスト/レスポンス兼用の構造体 */

    tap = PRIV(dev);
    /* TUN/TAP の制御用デバイスをオープン */
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1) {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    /* TAP デバイスの名前を設定 */
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name)-1);
    /* フラグ設定(IFF_TAP: TAPモード, IFF_NO_PI:パケット情報ヘッダを付けない */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    /* TAP デバイスの登録を要求 */
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
        errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    /* シグナル駆動I/Oのための設定 */
    /* Set Asynchronous I/O signal delivery destination */
    /* シグナルの配送先を設定 */
    if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    /* シグナル駆動I/Oを有効にする */
    /* Enable Asynchronous I/O */
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    /* 送信するシグナルを指定 */
    /* Use other signal instead of SIGIO */
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
        errorf("fcntl(FSETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    /* HW アドレスが明示的に設定されていなかったら */
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
        if (ether_tap_addr(dev) == -1) {
            errorf("ether_tap_addr() failure, dev=%s", dev->name);
            close(tap->fd);
            return -1;
        }
    }
    return 0;
}

/**
 * Ethernet デバイス（TAP）クローズ
 * @param [in,out] dev デバイス構造体ポインタ
 * @return
 */
static int
ether_tap_close(struct net_device *dev)
{
    /* ディスクリプタをクローズ */
    close(PRIV(dev)->fd);
    return 0;
}

/**
 * Ethernet デバイス(TAP)書き出し
 * @param [in,out] dev デバイス構造体ポインタ
 * @param [in] frame フレームのポインタ
 * @param [in] flen フレームサイズ
 * @return
 */
static ssize_t
ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->fd, frame, flen);
}

/**
 * Ethernet デバイス(TAP)送信関数
 * @param [in,out] dev デバイス構造体ポインタ
 * @param [in] type 
 * @param [in] buf
 * @param [in] len
 * @param [in] dst
 * @return
 */
int
ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

/**
 * Ethernet デバイス(TAP)読みだし
 * @param [in,out] dev デバイス構造体ポインタ
 * @param [in,out] buf 読みだしバッファ
 * @param [in] size 読みだしデータサイズ
 * @return 読みだしデータサイズ
 */
static ssize_t
ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size)
{
    ssize_t len;

    /* read で読みだすだけ */
    len = read(PRIV(dev)->fd, buf, size);
    if (len <= 0) {
        if (len == -1 && errno != EINTR) {
            errorf("read: %s, dev=%s", strerror(errno), dev->name);
        }
        return -1;
    }
    return len;
}

/**
 * Ethernet デバイス(TAP)割り込みハンドラ
 */
static int
ether_tap_isr(unsigned int irq, void *id)
{
    struct net_device *dev;
    struct pollfd pfd;
    int ret;

    dev = (struct net_device *)id;
    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;
    while (1) {
        /* タイムアウト時間を0に設定した poll() で読み込み可能なデータの存在を確認 */
        ret = poll(&pfd, 1, 0);
        if (ret == -1) {
            if (errno == EINTR) {
                /* errno が EINTR の場合は再試行 (シグナルに割り込まれたという回復可能なエラー) */
                continue;
            }
            errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            return -1;
        }
        /* 戻り値が0だったらタイムアウト(読み込み可能なデータなし) */
        if (ret == 0) {
            /* No frame to input immediately */
            break;
        }
        /* 読み込み可能だったら ether_input_heloer() を呼び出す */
        /* - コールバック関数として ehter_tap_read() のアドレスを渡す */
        ether_input_helper(dev, ether_tap_read);
    }
    return 0;
}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

/**
 * Ethernet デバイス(TAP) の生成と初期化
 * @param [in] name TAPデバイス名ポインタ
 * @param [in] addr ハードウェアアドレスの文字列ポインタ
 * @return デバイス構造体ポインタ
 */
struct net_device *
ether_tap_init(const char *name, const char *addr)
{
    struct net_device *dev;
    struct ether_tap  *tap;

    /* デバイスを生成 */
    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    /* Ethernet デバイスの共通パラメータを設定 */
    ether_setup_helper(dev);
    /* 引数でハードウェアアドレスの文字列が渡されたら */
    /* それをバイト列に変換して設定する */
    if (addr) {
        if (ether_addr_pton(addr, dev->addr) == -1) {
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }
    /* ドライバの関数群を設定 */
    dev->ops = &ether_tap_ops;
    /* ドライバ内部で使用するプライベートなデータを生成＆保持 */
    tap = memory_alloc(sizeof(*tap));
    if (!tap) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name)-1);
    tap->fd = -1; /* 初期値として無効な値(-1)を設定しておく */
    tap->irq = ETHER_TAP_IRQ;
    dev->priv = tap;
    /* デバイスをプロトコルスタックに登録 */
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        memory_free(tap);
        return NULL;
    }
    /* 割り込みハンドラの登録 */
    intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);
    infof("ethernet device initialized, dev=%s", dev->name);
    return dev;
}