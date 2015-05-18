#!/usr/sbin/dtrace -s

/*
http://dyjakan.sigsegv.pl/tracking-input-with-dtrace-on-os-x.html

TODO:
    o Add time stamps and sort via them?
*/

#pragma D option destructive
#pragma D option quiet

BEGIN
{
    trackedfd[0] = 0;
    trackedmmap[0] = 0;
}

pid$target::__open:entry
/copyinstr(arg0) == "/Users/ad/Desktop/test.mp3"/
{
    self->fname = copyinstr(arg0);
    self->openok = 1;
}

pid$target::__open:return
/self->openok/
{
    trackedfd[arg1] = 1;
    printf("Opening %s with fd %#x\n", self->fname, arg1);
    self->fname = 0;
    self->openok = 0;
}

pid$target::read:entry
/trackedfd[arg0] == 1/
{
    self->rfd = arg0;
    self->rbuf = arg1;
    self->rsz = arg2;
}

pid$target::read:return
/self->rfd/
{
    printf("Reading from fd %#p to buf %#p size %#x\n", self->rfd, self->rbuf, self->rsz);
    tracemem(copyin(self->rbuf, arg1), 64);
    ustack(); printf("\n");
    self->rfd = 0;
    self->rbuf = 0;
    self->rsz = 0;
}

pid$target::close:entry
/trackedfd[arg0] == 1/
{
    trackedfd[arg0] = 0;
}
