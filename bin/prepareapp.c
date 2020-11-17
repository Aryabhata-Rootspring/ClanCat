#include <stdio.h>
#include <unistd.h>  
int main(){
	system("sudo setcap cap_net_bind_service=ep /usr/bin/python3.9");
}
