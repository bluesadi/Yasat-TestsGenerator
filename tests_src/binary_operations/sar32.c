#include "stdint.h"

void sink(int32_t a){
}

int32_t sar32(int32_t a, int32_t b){
	return a >> b;
}

int main(){
	sink(sar32(1090281255, 18));
	sink(sar32(77127606, 23));
	sink(sar32(3023845612, 3));
	sink(sar32(3639567404, 16));
	sink(sar32(2904504299, 13));
	sink(sar32(4090200146, 21));
	sink(sar32(1399600190, 31));
	sink(sar32(2321455904, 10));
	sink(sar32(2992068734, 17));
	sink(sar32(2357003024, 19));
	sink(sar32(2084503284, 19));
	sink(sar32(993360339, 25));
	sink(sar32(4281910446, 17));
	sink(sar32(4043653640, 27));
	sink(sar32(1147670840, 5));
	sink(sar32(1875745874, 23));
	sink(sar32(3811947622, 15));
	sink(sar32(1737377876, 5));
	sink(sar32(794818885, 17));
	sink(sar32(1270918655, 25));
	sink(sar32(391335092, 24));
	sink(sar32(461715700, 19));
	sink(sar32(874924263, 2));
	sink(sar32(3806300152, 11));
	sink(sar32(3207342804, 4));
}

