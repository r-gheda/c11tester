#include <iostream>
#include <thread>
#include <atomic>
#include <cassert>

int a{0};

void accumulate()
{
    a = 1;
    a = 2;
    a = 3;
    a = 4;
    a = 5;
    a = 6;
}

void asse()
{
    assert(a != 5);
}

int main()
{
    std::thread thr1(accumulate);
    std::thread thr2(asse);
    thr1.join();
    thr2.join();
    std::cout << "Hello world" << a;
}