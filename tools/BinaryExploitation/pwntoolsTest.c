//gcc -m32 pwntoolsTest.c -o pwntoolsTest -fno-stack-protector -no-pie -mpreferred-stack-boundary=2 -fno-pic

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char* getCar()
{
        char buffer[48];
        gets(buffer);
        puts("You selected: \n");
        return buffer;
}

void secretCode()
{
    printf("You win a free car!!!");
    exit(0);
}

int main(int argc, char *argv[ ])
{
   char userSelection;
   printf("Good morning! Welcome to our online car purchasing system.  What would you like to do?\n"); 
   printf("1. Buy a car.\n");
   printf("2. Sell a car.\n");
   printf("3. Rent a scooter.\n");

   userSelection = getchar();
   getchar();

   switch(userSelection)
    {
        case '1':
            printf("What would you like to buy?\n");
            getCar();
            break;
        default:
            printf("That's not a valid option.\n");
    }

   return 0;
}

