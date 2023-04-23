#include "stdint.h"

void sink(int32_t a){
}

int32_t shl32(int32_t a, int32_t b){
	return a << b;
}

int main(){
	sink(shl32(3596749514, 11));
	sink(shl32(1788172172, 4));
	sink(shl32(35655212, 26));
	sink(shl32(341178068, 14));
	sink(shl32(725846567, 16));
	sink(shl32(3954686576, 29));
	sink(shl32(636252939, 17));
	sink(shl32(2387358156, 12));
	sink(shl32(3517542545, 8));
	sink(shl32(1673927327, 13));
	sink(shl32(2188500782, 23));
	sink(shl32(1791567181, 7));
	sink(shl32(1651797784, 13));
	sink(shl32(1315340791, 16));
	sink(shl32(3942609306, 0));
	sink(shl32(1919767334, 27));
	sink(shl32(1533844973, 26));
	sink(shl32(969537473, 12));
	sink(shl32(4108772109, 16));
	sink(shl32(42039351, 28));
	sink(shl32(1819464259, 18));
	sink(shl32(3822127673, 7));
	sink(shl32(3326948712, 7));
	sink(shl32(2671718907, 27));
	sink(shl32(1364582269, 8));
}

