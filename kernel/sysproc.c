#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"

uint64
sys_interpose(void)
{
  int mask;
  char path[MAXPATH];
  struct proc *p = myproc();

  argint(0, &mask);
  if(argstr(1, path, MAXPATH) < 0)
    return -1;

  p->syscall_mask = mask;
  safestrcpy(p->syscall_path, path, sizeof(p->syscall_path));
  return 0;
}

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0; // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if (t == SBRK_EAGER || n < 0) {
    if (growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if (addr + n < addr)
      return -1;
    if (addr + n > TRAPFRAME)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  backtrace();
  int n;
  uint ticks0;

  argint(0, &n);
  if (n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n) {
    if (killed(myproc())) {
      release(&tickslock);
      return -1;
    }
    sleep_prepare(&ticks);
    release(&tickslock);
    sleep();
    acquire(&tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

#ifdef LAB_PGTBL //added for task 3 detecting accessed pages
int
sys_pgaccess(void)
{
  uint64 base;   // first user va to check
  int len;       // number of pages
  uint64 mask;   // user addr of result bitmask
  argaddr(0, &base);
  argint(1, &len);
  argaddr(2, &mask);

  if(len < 0 || len > 64)         // one uint64 of bits
    return -1;

  struct proc *p = myproc();
  uint64 bits = 0;

  for(int i = 0; i < len; i++){
    pte_t *pte = walk(p->pagetable, base + (uint64)i * PGSIZE, 0);
    if(pte == 0 || (*pte & PTE_V) == 0)   // unmapped / invalid page
      return -1;
    if(*pte & PTE_A){
      bits |= (1UL << i);
      *pte &= ~PTE_A;             // clear so the next call reports fresh accesses
    }
  }

  if(copyout(p->pagetable, mask, (char*)&bits, sizeof(bits)) < 0)
    return -1;    // invalid buffer address
  return 0;
}
#endif

uint64
sys_sigalarm(void)
{
  int ticks;
  uint64 handler;
  struct proc *p = myproc();

  argint(0, &ticks);
  argaddr(1, &handler);

  p->alarm_interval = ticks;
  p->ticks_left = ticks;
  p->alarm_handler = handler;
  return 0;
}

uint64
sys_sigreturn(void)
{
  struct proc *p = myproc();

  *(p->trapframe) = *(p->saved_tf);
  kfree((void*)p->saved_tf);
  p->saved_tf = 0;
  p->alarm_in_progress = 0;
  return p->trapframe->a0;
}