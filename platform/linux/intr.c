/**
 * 割り込み処理
*/
/* pthread_barrier_t でエラーとならないための暫定処置 */
#define _XOPEN_SOURCE 600 /* Or higher */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "platform.h"

#include "util.h"

/**
 * 割り込み要求 (IRQ) の構造体
 * - デバイスと同様にリスト構造で管理する
*/
struct irq_entry {
    /* 次の IRQ 構造体へのポインタ */
    struct irq_entry *next;
    /* 割り込み番号 (IRQ番号) */
    unsigned int irq;
    /* 割り込みハンドラ (割り込みが発生した際に呼び出す関数へのポインタ) */
    int (*handler)(unsigned int irq, void *dev);
    /* フラグ (INTR_IRQ_SHARED が指定された場合は IRQ 番号を共有可能) */
    int flags;
    /* デバッグ出力で識別するための名前 */
    char name[16];
    /* 割り込みの発生元となるデバイス (struct net_device 以外にも対応できるように void* で保持) */
    void *dev;
};

/* IRQリスト (リストの先頭を指すポインタ) */
/* NOTE: if you want to add/delete the entries after intr_run(), you need to protect these lists with a mutex. */
static struct irq_entry *irqs;

/* シグナル集合 (シグナルマスク用) */
static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

/* 割り込み処理スレッドのスレッドID */
static pthread_t tid;

/* シグナルマスク用のシグナル集合 */
static sigset_t sigmask;

/* 割り込みスレッドのスレッドID */
static pthread_t tid;
/* スレッド間の同期のためのバリア */
static pthread_barrier_t barrier;

/**
 * 割り込みハンドラの登録
*/
int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next) {
        /* IRQ番号が既に登録されている場合、IRQ番号の共有が許可されているかどうかチェック */
        if (entry->irq == irq) {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                /* どちらかが共有を許可していない場合はエラーを返す */
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }

    /* IRQ リストへ新しいエントリを追加 */
    /* 新しいエントリのメモリを確保*/
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    /* IRQ 構造体に値を設定 */
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name)-1);
    entry->dev = dev;
    /* IRQリストの先頭へ挿入 */
    entry->next = irqs;
    irqs = entry;
    /* シグナル集合へ新しいシグナルを追加 */
    sigaddset(&sigmask, irq);
    debugf("registered: irq=%u, name=%s", irq, name);
}

/**
 * 割り込み処理の発生
*/
int
intr_raise_irq(unsigned int irq)
{
    /* 割り込み処理スレッドへシグナルを送信 */
    return pthread_kill(tid, (int)irq);
}

/**
 * 割り込みスレッドのエントリポイント
 * 割り込みの補足と振り分け
*/
static void *
intr_thread(void *arg)
{
    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start...");
    /* メインスレッドと同期をとるための処理 */
    pthread_barrier_wait(&barrier);
    while (!terminate) {
        /* 割り込みに見立てたシグナルが発生するまで待機 */
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }

        /* 発生したシグナルの種類に応じた処理 */
        switch (sig) {
            /* SIGHUP: 割り込みスレッドへ終了を通知するためのシグナル */
            case SIGHUP:
                /* terminate を 1 にしてループを抜ける */
                terminate = 1;
                break;
            default:
                /* デバイス割り込み用のシグナル */
                /* IRQ リストを巡回 */
                for (entry = irqs; entry; entry = entry->next) {
                    /* IRQ 番号が一致するエントリの割り込みハンドラを呼び出す */
                    if (entry->irq == (unsigned int)sig) {
                        debugf("irq=%d, name=%s", entry->irq, entry->name);
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");
    return NULL;
}

/**
 * 割り込み機構の起動
*/
int
intr_run(void)
{
    int err;

    /* シグナルマスクの設定 */
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    /* 割り込み処理スレッドの起動 */
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    /* スレッドが動き出すまで待つ */
    /* (他のスレッドが同じように pthread_barrier_wait() を呼び出し、
        バリアのカウントが指定の値になるまでスレッドを停止する) */
    pthread_barrier_wait(&barrier);
    return 0;
}

/**
 * 割り込み機構の停止
 */
void
intr_shutdown(void)
{
    /* 割り込み処理スレッドが起動済みかどうか確認 */
    if (pthread_equal(tid, pthread_self()) != 0) {
        /* Thread not created. */
        return;
    }
    /* 割り込み処理スレッドにシグナル(SIGHUP)を送信 */
    pthread_kill(tid, SIGHUP);
    /* 割り込み処理スレッドが完全に終了するのを待つ */
    pthread_join(tid, NULL);
}

/**
 * 割り込み機構の初期化
*/
int
intr_init(void)
{
    /* スレッドIDの初期値にメインスレッドのIDを設定する */
    tid = pthread_self();
    /* pthread_barrier の初期化 (カウントを2に設定) */
    pthread_barrier_init(&barrier, NULL, 2);
    /* シグナル集合を初期化(空にする) */
    sigemptyset(&sigmask);
    /* シグナル集合に SIGHUP を追加 (割り込みスレッド終了通知用) */
    sigaddset(&sigmask, SIGHUP);
    return 0;
}