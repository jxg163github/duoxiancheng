from threading import Thread
from multiprocessing import Process
import os

def work():
    print('hello1',os.getpid())
def work2():
    print('hello2',os.getpid())
if __name__ == '__main__':
    #part1:在主进程下开启多个线程,每一个线程都跟主进程的pid同样
    t1=Thread(target=work)
    t2=Thread(target=work2)
    t1.start()
    t2.start()
    print('主线程/主进程pid',os.getpid())

    #part2:开多个进程,每一个进程都有不一样的pid
    p1=Process(target=work)
    p2=Process(target=work2)
    p1.start()
    p2.start()
    print('主线程/主进程pid',os.getpid())

