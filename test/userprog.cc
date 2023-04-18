#include <iostream>
#include <thread>
#include <atomic>
#include <cassert>

std::atomic_int a{0};

void accumulate()
{
    a.store(1, std::memory_order_relaxed);
    a.store(2, std::memory_order_relaxed);
    a.store(3, std::memory_order_relaxed);
    a.store(4, std::memory_order_relaxed);
    a.store(5, std::memory_order_relaxed);
    a.store(6, std::memory_order_relaxed);
}

void asse()
{
    int temp = a.load(std::memory_order_relaxed);
    assert(temp != 2);
}

int main()
{
    std::thread thr1(accumulate);
    std::thread thr2(asse);
    thr1.join();
    thr2.join();
    // std::cout << "Hello world" << a;
}