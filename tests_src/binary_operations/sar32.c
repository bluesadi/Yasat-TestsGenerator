#include "stdint.h"

void sink(int32_t a){
}

int32_t sar32(int32_t a, int32_t b){
	return a >> b;
}

int main(){
	sink(sar32(1168901516, 18));
	sink(sar32(1415194375, 14));
	sink(sar32(1115461355, 15));
	sink(sar32(2765314904, 4));
	sink(sar32(3586137205, 30));
	sink(sar32(2451690885, 28));
	sink(sar32(55550700, 18));
	sink(sar32(2228524966, 29));
	sink(sar32(3471647021, 1));
	sink(sar32(3572527800, 26));
	sink(sar32(3334359247, 28));
	sink(sar32(1955620178, 18));
	sink(sar32(2142086301, 4));
	sink(sar32(2184321720, 18));
	sink(sar32(665055857, 27));
	sink(sar32(3611514877, 2));
	sink(sar32(2524236177, 6));
	sink(sar32(2155956867, 26));
	sink(sar32(2615287423, 13));
	sink(sar32(991327541, 7));
	sink(sar32(488439327, 9));
	sink(sar32(2883779766, 21));
	sink(sar32(1055465881, 27));
	sink(sar32(1864771641, 26));
	sink(sar32(786679676, 12));
}

