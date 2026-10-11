/* Disposable unprivileged experiment. Never embed or install this fixture. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
static int report(uint32_t tag,uint32_t detail){uint32_t r[3]={0x524d5431,tag,detail};return write(5,r,sizeof r)==sizeof r?0:1;}
static int report_exec_error(int failure_fd,int pending_allowed){
 int failed=0;ssize_t count;
 do{count=read(failure_fd,&failed,sizeof failed);}while(count<0&&errno==EINTR);
 if(count<0)return pending_allowed&&errno==EAGAIN?0:1;
 if(count!=0&&count!=sizeof failed)return 1;
 if(count==sizeof failed&&(failed<=0||report('F',(uint32_t)failed)))return 1;
 return 0;
}
static int report_reaped_target(int failure_fd,uint32_t status){
 return report_exec_error(failure_fd,0)||report('X',status);
}
int main(int argc,char **argv){
 if(argc!=2||getsid(0)!=getpid()||ioctl(0,TIOCSCTTY,0))return 70;
 signal(SIGTTOU,SIG_IGN);signal(SIGPIPE,SIG_IGN);
 int gate[2],failure[2];if(pipe(gate)||pipe(failure))return 71;
 for(int i=0;i<2;i++){fcntl(gate[i],F_SETFD,FD_CLOEXEC);fcntl(failure[i],F_SETFD,FD_CLOEXEC);}
 pid_t target=fork();if(target<0)return 72;
 if(target==0){
  close(gate[1]);close(failure[0]);close(5);close(6);
  unsigned char byte;if(read(gate[0],&byte,1)!=1||byte!=1)_exit(74);close(gate[0]);
  if(getpgrp()!=getpid())_exit(73);
  signal(SIGTTOU,SIG_DFL);signal(SIGPIPE,SIG_DFL);
  char *args[]={argv[1],NULL};char *environment[]={NULL};execve(argv[1],args,environment);
  int error=errno;(void)write(failure[1],&error,sizeof error);_exit(127);
 }
 close(gate[0]);close(failure[1]);fcntl(failure[0],F_SETFL,O_NONBLOCK);
 int events=kqueue(),error=0;struct kevent change;
 EV_SET(&change,target,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_CLEAR,NOTE_EXEC|NOTE_EXIT,0,NULL);
 if(events<0||kevent(events,&change,1,NULL,0,NULL)||setpgid(target,target)||tcsetpgrp(0,target))error=1;
 if(!error&&report('R',(uint32_t)target))error=1;
 unsigned char release=0;if(!error&&(read(6,&release,1)!=1||release!=1))error=1;close(6);
 if(!error&&write(gate[1],&release,1)!=1)error=1;close(gate[1]);
 if(error)kill(-target,SIGKILL);
 int status=0,exec_seen=0,reaped=0,ownership_lost=0;
 for(int i=0;i<10000&&!reaped;i++){
  struct kevent event;struct timespec immediate={0,0};int count=kevent(events,NULL,0,&event,1,&immediate);
  if(count<0&&errno!=EINTR){error=1;kill(-target,SIGKILL);}
  if(count==1&&(event.fflags&NOTE_EXEC)&&!exec_seen){exec_seen=1;if(report('E',0))error=1;}
  if(report_exec_error(failure[0],1)){error=1;break;}
  pid_t got=waitpid(target,&status,WNOHANG|WUNTRACED|WCONTINUED);
  if(got==target){
   if(WIFSTOPPED(status)){if(report('S',(uint32_t)WSTOPSIG(status)))error=1;}
   else if(WIFCONTINUED(status)){if(report('C',0))error=1;}
   else {reaped=1;if(report_reaped_target(failure[0],(uint32_t)status))error=1;}
  }else if(got<0&&errno!=EINTR){if(errno==ECHILD)ownership_lost=1;error=1;break;}
  if(error&&!reaped)kill(-target,SIGKILL);
  usleep(1000);
 }
 if(!reaped&&!ownership_lost){kill(-target,SIGKILL);while(waitpid(target,&status,0)<0&&errno==EINTR){};error=1;}
 close(events);close(failure[0]);close(5);return error?75:0;
}
