#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
// for exit, thread_exit(), thread_remove()
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"
/* week2-2 */

// for create, filesys_creat()
#include "filesys/filesys.h"
// for halt(), power_down()
#include "threads/init.h"
/* week2-2 */
/*week2-4*/
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/palloc.h"

/*week2-4*/

/*week2-4*/
struct lock filesys_lock;
/*week2-4*/




void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* week2-2 */
int check_address(void *addr);
//system call 함수들
void halt (void);
void exit(int status);
bool create (const char *file , unsigned initial_size);
bool remove (const char *file);
/* week2-2 */
/* week2-4 */
int open (const char *file);
int filesize (int fd);
void seek (int fd, unsigned postion);
unsigned tell (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void close (int fd);
int fork (const char *thread_name, struct intr_frame *_if);

/* week2-4 */

/*week2-3*/
int wait (tid_t given_tid);
/*week2-3*/


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* week2-2 */

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	// rsp의 값이 주소로써 유저의 스택영역을 가리키고 있는지 검토
	// if (!check_address(f->rsp)){ 
	// 	// printf("유저 스택 영역의 rsp가 아니거나 할당되어 있지 않습니다!\n");
	// 	exit(-1);
	// }
	// a1 = f->R.rdi
	// a2 = f->R.rsi
	// a3 = f->R.rdx
	// a4 = f->R.r10
	// a5 = f->R.r8
	// a6 = f->R.r9

	// rax가 갖고 있는 시스템 콜 넘버에 따른 시스템 콜 호출
	switch((int)f->R.rax){

		case (SYS_HALT) :
		halt();
		break;

		case (SYS_EXIT):
		exit(f->R.rdi);
		break;

		case (SYS_CREATE):
		if (!check_address(f->R.rdi)){ 
			// printf("create() 시스템 콜의 인자의 데이터가 유저영역에 있지 않습니다!\n");
			exit(-1);
		}
		f->R.rax = create (f->R.rdi,f->R.rsi);
		break;

		case (SYS_REMOVE):
		if (!check_address(f->R.rdi)){ 
			// printf("remove() 시스템 콜의 인자의 데이터가 유저영역에 있지 않습니다!\n");
			exit(-1);
		}
		f->R.rax = remove(f->R.rdi);
		break;

		case (SYS_OPEN):
		if (!check_address(f->R.rdi)){ 
			// printf("open() 시스템 콜의 인자의 데이터가 유저영역에 있지 않습니다!\n");
			exit(-1);
		}
		f->R.rax = open(f->R.rdi);
		break;
		
		case (SYS_FILESIZE):
		f->R.rax = filesize(f->R.rdi);
		break;
		
		case (SYS_SEEK):
		seek (f->R.rdi, f->R.rsi);
		break;

		case (SYS_TELL):
		f->R.rax = tell(f->R.rdi);
		break;

		case (SYS_READ):
		if (!check_address(f->R.rsi)){ 
			// printf("read() 시스템 콜의 인자의 데이터가 유저영역에 있지 않습니다!\n");
			exit(-1);
		}
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

		case (SYS_WRITE):
		if (!check_address(f->R.rsi)){ 
			// printf("write() 시스템 콜의 인자의 데이터가 유저영역에 있지 않습니다!\n");
			exit(-1);
		}
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

		case (SYS_CLOSE):
		close(f->R.rdi);
		break;

		case (SYS_WAIT):
		f->R.rax = wait(f->R.rdi);
		break;
		
		case (SYS_FORK):
		if (!check_address(f->R.rdi)){ 
			exit(-1);
		}
		// 복제를 시도하는 프로세스의 인터럽트 프레임을 전달
		f->R.rax = fork(f->R.rdi, f);
		break;

		case (SYS_EXEC):
		if (!check_address(f->R.rdi)){ 
			exit(-1);
		}
		f->R.rax = exec(f->R.rdi);
		break;


		default :
		exit(-1);
	}


	// thread_exit ();
}
void halt (void){
	power_off();
}

int exec(const char *file) {

	int file_size = strlen(file)+1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if(fn_copy == NULL ) {
		//OOM 수정 4 : 아래 줄 추가
		// palloc_free_page(fn_copy);
		exit(-1);
	}
	strlcpy(fn_copy, file, file_size);

	if(process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

int fork (const char *thread_name, struct intr_frame *_if) {
	return process_fork(thread_name, _if);
}
int wait (tid_t given_tid){
	return process_wait(given_tid);
}

void exit (int to_status){
	struct thread *curr = thread_current();
	curr ->exit_code = to_status;
	printf("%s: exit(%d)\n", thread_name(), curr->exit_code);
	thread_exit();
}
bool create (const char *file , unsigned initial_size){
	// lock_acquire(&filesys_lock);
	bool success = filesys_create (file, initial_size);
	// lock_release(&filesys_lock);
	return success;
}
bool remove (const char *file){
	// lock_acquire(&filesys_lock);
	bool success = filesys_remove(file);
	// lock_release(&filesys_lock);
	return success;
}
int read (int fd, void *buffer, unsigned size){
	// fd값을 이용하여 현재 thread의 fdt를 조회하여 해당 파일의 구조체를 가져온다
	struct file *file_name = process_get_file(fd);
	// 읽은 byte 수 -> 나중에 리턴값
	int byte_read=0;
	//간단한 예외 처리
	if (size  <0 || file_name == NULL)
		return -1;
	// fd == 0 즉 표준 입력에 접근하는 경우
	if (fd == 0){
		unsigned char c;
		while (byte_read<size)
		{
			c = input_getc ();
			((unsigned char *)buffer)[byte_read++] = c;
			if (c == '\0')
				break;
		}
	}
	// 표준 출력에 접근하는 경우 
	else if (fd == 1)
	return -1;
	// 파일에 접근하는 경우
	else
	{
		lock_acquire(&filesys_lock);
		byte_read = file_read(file_name, buffer, size);
		lock_release(&filesys_lock);
	}
	return byte_read;
}

int write (int fd , void *buffer, unsigned size){
	// 예외처리
	if (size <0)
		return -1;
	// write는 표준입력에서 할일이 없다
	if (fd == 0){
		return -1;
	}
	// 표준 출력의 경우
	else if (fd == 1){
		putbuf((char *)buffer, size);
	}
	// 원하는 파일에 쓰는 경우
	else{
		// 파일 찾기
		struct file *filename = process_get_file(fd);
		if (filename==NULL)
			return -1;
		// 파일에 쓰기
		lock_acquire(&filesys_lock);
		int byte_writen = file_write(filename, buffer, size);
		lock_release(&filesys_lock);
		return byte_writen;
	}
}

int open (const char *file){
	int fd;
	// 파일을 테이블에 할당
	// lock_acquire(&filesys_lock);
	struct file *file_name = filesys_open(file);
	// lock_release(&filesys_lock);
	//테이블에 올리지 조차 못했다면 return -1
	if (file_name==NULL)
		return -1;
	//테이블에 올린 파일을 open을 요청한 process의 fdt에 추가
	fd = process_add_file(file_name);
	// fdt에 매핑하지 못했다면 테이블에할당한 file을 할당취소 file_close() 하고 return -1
	if (fd==-1){
		// lock_acquire(&filesys_lock);

		file_close(file_name);
		// lock_release(&filesys_lock);
		// return -1;
	}
	return fd;
}

void close (int fd){
	// 스레드의 fdt에서 파일 찾기
	struct file *filename = process_get_file(fd);
	if (filename == NULL)
		return;
	// 해당 thread의 fdt에서 이 파일의 descriptor 삭제
	process_close_file(fd);
	// fd가 표준 입출력을 나타낸다면 닫지 않는다.
	if (fd<=1 || filename <=2){
		return;
	}
	// file_close() : 함수 참조 알아서
	// lock_acquire(&filesys_lock);
	file_close(filename);
	// lock_release(&filesys_lock);
}

int filesize (int fd){
	struct file *file_id;
	// lock_acquire(&filesys_lock);
	file_id = process_get_file(fd);
	if (file_id == NULL)
		return -1;
	int size = file_length(file_id);
	// lock_release(&filesys_lock);
	return size; 
}
void seek (int fd, unsigned postion){
	// thread의 fdt에서 파일 찾기
	struct file *file_name = process_get_file(fd);
	if (file_name==NULL || postion <0 )
		return -1;
	// lock_acquire(&filesys_lock);
	file_seek (file_name, postion);
	// lock_release(&filesys_lock);
}

unsigned tell (int fd){
	struct file *file_name = process_get_file(fd);
	if (file_name ==NULL)
		return -1;
	// lock_acquire(&filesys_lock);
	unsigned offset = file_tell(file_name);
	// lock_release(&filesys_lock);
	return offset;
}

int check_address(void *addr){
	struct thread *t = thread_current();
	return (addr != NULL && is_user_vaddr (addr) && pml4_get_page (t->pml4, addr)!=NULL);
	// return   addr != NULL && is_user_vaddr (addr);
}
/* week2-2 */


