#include "stdint.h"

void sink(uint32_t a){
}

uint32_t shr32(uint32_t a, uint32_t b){
	return a >> b;
}

int main(){
	sink(shr32(22602035, 15));
	sink(shr32(3689135180, 14));
	sink(shr32(2173719302, 24));
	sink(shr32(1092720371, 1));
	sink(shr32(3315490958, 21));
	sink(shr32(839580461, 23));
	sink(shr32(1521399705, 19));
	sink(shr32(3822948875, 12));
	sink(shr32(1729134745, 25));
	sink(shr32(2438258811, 5));
	sink(shr32(1046830099, 16));
	sink(shr32(1170613033, 17));
	sink(shr32(2229274612, 21));
	sink(shr32(2102782698, 6));
	sink(shr32(2988288419, 31));
	sink(shr32(3658228056, 21));
	sink(shr32(203670079, 13));
	sink(shr32(2125796760, 8));
	sink(shr32(2417140438, 13));
	sink(shr32(3189266982, 4));
	sink(shr32(2224703220, 9));
	sink(shr32(890448876, 1));
	sink(shr32(885894701, 29));
	sink(shr32(3477968077, 17));
	sink(shr32(289347109, 26));
}

