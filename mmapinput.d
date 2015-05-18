#!/usr/sbin/dtrace -s

/*
Tracking mmap() instead of read(). This introduced certain obstacle as explained
in the comments, thus I'm saving it as an example.

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
/copyinstr(arg0) == "/Users/ad/Desktop/test"/
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

pid$target::__mmap:entry
/trackedfd[arg4] == 1/
{
    self->msz = arg1;
    self->mfd = arg4;
}

pid$target::__mmap:return
/self->msz/
{
    trackedmmap[arg1] = 1;
    printf("Mapping fd %#x to %#p size %#x\n", self->mfd, arg1, self->msz);
    ustack(); printf("\n");
}


pid$target::__munmap:entry
/trackedmmap[arg0] == 1/
{
    printf("Unmapping %#p\n", arg0);

/* 
I peek at mmaped memory here and not at mmap() because DTrace cannot peek
at memory that has not been touched. See "Avoiding Errors" [1].

[1] https://wikis.oracle.com/display/DTrace/User+Process+Tracing
*/
    tracemem(copyin(arg0, arg2), 128);
    
    self->msz = 0;
    self->mfd = 0;
    trackedmmap[arg0] = 0;
}

pid$target::close:entry
/trackedfd[arg0] == 1/
{
    trackedfd[arg0] = 0;
}

