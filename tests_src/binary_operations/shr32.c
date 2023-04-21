#include "stdint.h"

void sink(uint32_t a){
}

uint32_t shr32(uint32_t a, uint32_t b){
	return a >> b;
}

int main(){
	sink(shr32(4266106217, 4));
	sink(shr32(1609260113, 21));
	sink(shr32(71489417, 10));
	sink(shr32(4119936390, 22));
	sink(shr32(2191130061, 27));
	sink(shr32(4101405753, 21));
	sink(shr32(3744272178, 13));
	sink(shr32(530189548, 12));
	sink(shr32(1351211873, 24));
	sink(shr32(3084978489, 18));
	sink(shr32(2908133217, 31));
	sink(shr32(3191322852, 18));
	sink(shr32(3790427483, 3));
	sink(shr32(2116427111, 16));
	sink(shr32(3047984645, 2));
	sink(shr32(1160644063, 27));
	sink(shr32(2638648010, 1));
	sink(shr32(1332378788, 12));
	sink(shr32(3710525709, 27));
	sink(shr32(3916146668, 3));
	sink(shr32(4024087783, 2));
	sink(shr32(104129852, 7));
	sink(shr32(1113264936, 9));
	sink(shr32(566500926, 10));
	sink(shr32(2490192276, 28));
}

