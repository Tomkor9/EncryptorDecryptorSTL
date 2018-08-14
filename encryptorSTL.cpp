// encryptorSTL.cpp : Defines the entry point for the console application.
//

#include "Cryptographic.h"
#include <iostream>


int main()
{
	Cryptographic c;
	c.crypt("text.txt", true);
	c.decrypt("text.txt", true);

	std::cin.get();
    return 0;
}

