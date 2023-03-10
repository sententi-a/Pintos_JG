#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H


/*week2-3*/
// struct thread에 semaphore을 추가히기 위한 전처리
#include "threads/synch.h"
/*week2-3*/

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
// struct PCB {

// }

struct for_wait {
	tid_t tid;                          /* Thread identifier. */
	struct list_elem child_elem;
	// 종료되었는지
	int is_exit;
	// 어떤 exit_code 상태로 종료되었는지
	int exit_code;
	// wait 작업을 위한 semaphore
	struct semaphore wait_sema;
	struct thread *self;
};

struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	/*week1-1*/
	int64_t wakeup_tick;				/* time to wake up */
	/*week1-1*/
	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
	/* week1-4 수정 */
	int priority_before; // donation 전의 priority
	struct list donations; // multiple donation 상황을 위한 list(donation해준 애들 들어있음)
	struct list_elem d_elem; // multiple donation을 위한 donations(list)의 성분으로 사용하기 위한 list_elem
	struct lock *wait_on_lock_p; // 해당 스레드가 얻기 위해 대기중인 lock의 자료구조를 가리키는 포인터
	/* week1-4 수정 */

	//wait수정
	struct for_wait *for_wait;

	/*week2-4*/
	// close/write/를 위한 running
	struct file *running;
	/*week2-4*/

	/* week2-3 */
	// exec 작업을 위한 semaphore
	struct semaphore exec_sema;

	// 부모가 자식의 정보를 조회하는 것을 기다리기 위한 세마
	struct semaphore for_parent;
	// 부모의 thread pointer
	// struct thread *parent;
	// child list와 child elem
	struct list child_list;

	/* week2-3 */

	/*week2-4*/
	struct file **fdt;
	int next_fd;
	// 자식에게 본인의 인터럽트 프레임을 건내기 위해 만든 멤버
	struct intr_frame parent_if;
	/*week2-4*/

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

void thread_sleep(int64_t ticks);
void thread_awake(int64_t ticks);
void update_next_tick_to_awake(void);
int64_t get_next_tick_to_awake(void);

void test_max_priority(void);
bool cmp_priority(struct list_elem *a, struct list_elem *b, void *aux UNUSED);

/* week1-4 추가함수*/
void donate_priority (void);
void remove_with_lock(struct lock *lock);
void refresh_priority (void);
/* week1-4 추가함수*/

#endif /* threads/thread.h */


