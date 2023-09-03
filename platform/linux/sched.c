#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

/**
 * タスクスケジュール構造体の初期化
 * @param [in,out] ctx タスクスケジュール構造体ポインタ
 * @return 0
 */
int
sched_ctx_init(struct sched_ctx *ctx)
{
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0;
    ctx->wc = 0;
    return 0;
}

/**
 * タスクスケジュール構造体の条件変数の破棄
 * @param [in,out] ctx タスクスケジュール構造体ポインタ
 * @return 待機中のスレッドが存在する場合にのみエラーが返る
 */
int
sched_ctx_destroy(struct sched_ctx *ctx)
{
    return pthread_cond_destroy(&ctx->cond);
}

/**
 * タスクの休止
 * @param [in,out] ctx タスクスケジュール構造体ポインタ
 * @param [in,out] mutex
 * @param [in] abstime 絶対時刻
 * @return エラー(-1)は sched_interrupt()による起床
 */
int
sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
    int ret;

    /* interrupted のフラグが立っていたら errno に ENTER を設定してエラーを返す */
    if (ctx->interrupted) {
        errno = EINTR;
        return -1;
    }
    /* wait カウントをインクリメント */
    ctx->wc++;
    /* pthread_cond_broadcast() が呼ばれるまでスレッドを休止させる */
    /* abstime が指定されていたら指定時刻に起床する pthread_cond_timedwait() を使用する */
    /* ※休止する際には mutex がアンロックされ、起床する際にロックされた状態で戻ってくる */
    if (abstime) {
        ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
    } else {
        ret = pthread_cond_wait(&ctx->cond, mutex);
    }
    ctx->wc--;
    if (ctx->interrupted) {
        /* 休止中だったスレッドが全て起床したら interrupted フラグを下げる */
        if (!ctx->wc) {
            ctx->interrupted = 0;
        }
        /* errno に EINTR を設定してエラーを返す */
        errno = EINTR;
        return -1;
    }
    return ret;
}

/**
 * タスクの起床
 */
int
sched_wakeup(struct sched_ctx *ctx)
{
    /* 休止しているスレッドを起床させる */
    return pthread_cond_broadcast(&ctx->cond);
}

/**
 * タスクの割り込み
 */
int
sched_interrupt(struct sched_ctx *ctx)
{
    /* interrupted フラグを立てた上で休止しているスレッドを起床させる */
    ctx->interrupted = 1;
    return pthread_cond_broadcast(&ctx->cond);
}