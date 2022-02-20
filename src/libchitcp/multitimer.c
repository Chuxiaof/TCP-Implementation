/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "chitcp/multitimer.h"
#include "chitcp/log.h"

struct worker_args
{
    multi_timer_t *mt;
};

void *multiple_timer_machine(void *args);

static int timespec_cmp(single_timer_t * timer_x, single_timer_t * timer_y)
{   
    struct timespec *x= &timer_x->expire_time;
    struct timespec *y= &timer_y->expire_time;
    if (x->tv_sec < y->tv_sec)
    {
        return -1;
    }
    else if (x->tv_sec > y->tv_sec)
    {
        return 1;
    }
    return x->tv_nsec - y->tv_nsec;
}

/* See multitimer.h */
void timespec_add(struct timespec *expire_time, uint64_t timeout)
{
    long secs = timeout / (long)1e9;
    long nsec = timeout % (long)1e9;
    clock_gettime(CLOCK_REALTIME, expire_time);
    long temp = expire_time->tv_nsec + nsec;
    expire_time->tv_sec += secs + temp / (long)1e9;
    expire_time->tv_nsec = temp % (long)1e9;
}

/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec)
    {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec > SECOND)
    {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec;
}

/* See multitimer.h */
int mt_init(multi_timer_t *mt, uint16_t num_timers)
{
    mt->timer_num = num_timers;

    mt->all_timers = calloc(num_timers, sizeof(single_timer_t));
    if (mt->all_timers == NULL)
    {
        return CHITCP_ENOMEM;
    }
    uint16_t id = 0;
    for (uint16_t i = 0; i < num_timers; i++)
    {
        single_timer_t *cur = &mt->all_timers[i];
        cur->id = id++;
        cur->active = false;
    }

    mt->active_timers = NULL;
    pthread_mutex_init(&mt->lock, NULL);
    pthread_cond_init(&mt->condvar, NULL);

    /* create multi-timer thread */
    struct worker_args *wa = calloc(1, sizeof(struct worker_args));
    wa->mt = mt;
    if (pthread_create(&mt->multiple_timer_thread, NULL, multiple_timer_machine, wa) != 0)
    {
        chilog(ERROR, "Could not create a multitimer thread");
        free(wa);
        pthread_exit(NULL);
        return CHITCP_ETHREAD;
    }
    return CHITCP_OK;
}

/* See multitimer.h */
int mt_free(multi_timer_t *mt)
{
    if (mt)
    {
        // stop the timer thread
        pthread_cancel(mt->multiple_timer_thread);
        // free related memory
        pthread_cond_destroy(&mt->condvar);
        pthread_mutex_destroy(&mt->lock);
        free(mt->all_timers);
    }
    return CHITCP_OK;
}

/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer)
{
    if (id < 0 || id >= mt->timer_num)
    {
        return CHITCP_EINVAL;
    }
    *timer = &mt->all_timers[id];
    return CHITCP_OK;
}

/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, mt_callback_func callback, void *callback_args)
{
    single_timer_t *timer;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_EINVAL || timer->active)
    {
        return CHITCP_EINVAL;
    }

    pthread_mutex_lock(&mt->lock);
    timer->active = true;
    timer->callback = callback;
    timer->callback_args = callback_args;
    timespec_add(&timer->expire_time, timeout);
    LL_INSERT_INORDER(mt->active_timers, timer, timespec_cmp);
    pthread_cond_signal(&mt->condvar);
    pthread_mutex_unlock(&mt->lock);

    return CHITCP_OK;
}

/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    single_timer_t *timer;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_EINVAL || !timer->active)
    {
        return CHITCP_EINVAL;
    }

    pthread_mutex_lock(&mt->lock);
    timer->active = false;
    LL_DELETE(mt->active_timers, timer);
    timer->next = NULL;
    pthread_cond_signal(&mt->condvar);
    pthread_mutex_unlock(&mt->lock);

    return CHITCP_OK;
}

/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    /* Your code here */
    single_timer_t *timer;
    if (mt_get_timer_by_id(mt, id, &timer) == CHITCP_EINVAL || !timer->active)
    {
        return CHITCP_EINVAL;
    }
    
    pthread_mutex_lock(&mt->lock);
    strncpy(timer->name, name, strlen(name));
    pthread_mutex_unlock(&mt->lock);
    return CHITCP_OK;
}

/* mt_chilog_single_timer - Prints a single timer using chilog
 *
 * level: chilog log level
 *
 * timer: Timer
 *
 * Returns: Always returns CHITCP_OK
 */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);

    if (timer->active)
    {
        /* Compute the appropriate value for "diff" here; it should contain
         * the time remaining until the timer times out.
         * Note: The timespec_subtract function can come in handy here*/
        struct timespec *res;
        timespec_subtract(res, &timer->expire_time, &now);
        diff.tv_sec = res->tv_sec;
        diff.tv_nsec = res->tv_nsec;
        chilog(level, "%i %s %lis %lins", timer->id, timer->name, diff.tv_sec, diff.tv_nsec);
    }
    else
        chilog(level, "%i %s", timer->id, timer->name);

    return CHITCP_OK;
}

/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only)
{
    if (active_only) {
        pthread_mutex_lock(&mt->lock);
        single_timer_t *el;
        LL_FOREACH(mt->active_timers, el) {
            mt_chilog_single_timer(level, el);
        }
        pthread_mutex_unlock(&mt->lock);
    } else {
        for (int i = 0; i < mt->timer_num; i++) {
            mt_chilog_single_timer(level, &mt->all_timers[i]);
        }
    }
    return CHITCP_OK;
}

void *multiple_timer_machine(void *args)
{
    struct worker_args *wa = (struct worker_args *)args;
    multi_timer_t *mt = wa->mt;

    while (true)
    {
        pthread_mutex_lock(&mt->lock);
        if (!mt->active_timers)
        {
            pthread_cond_wait(&mt->condvar, &mt->lock);
        }
        else
        {
            single_timer_t *first_timer = mt->active_timers;
            int rv = pthread_cond_timedwait(&mt->condvar, &mt->lock, &first_timer->expire_time);
            if (rv == ETIMEDOUT)
            {   
                first_timer->num_timeouts++;
                first_timer->callback(mt, first_timer, first_timer->callback_args);
                first_timer->active = false;
                LL_DELETE(mt->active_timers, first_timer);
                first_timer->next = NULL;
            }
        }
        pthread_mutex_unlock(&mt->lock);
    }
}