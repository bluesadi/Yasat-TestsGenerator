#include "stdint.h"

void sink(int32_t a){
}

int32_t shl32(int32_t a, int32_t b){
	return a << b;
}

int main(){
	sink(shl32(358706286, 0));
	sink(shl32(2613538618, 14));
	sink(shl32(1075565538, 25));
	sink(shl32(268602581, 20));
	sink(shl32(3531441565, 18));
	sink(shl32(3638245810, 7));
	sink(shl32(4166896955, 24));
	sink(shl32(2136485408, 2));
	sink(shl32(2555994316, 5));
	sink(shl32(504854616, 10));
	sink(shl32(753396919, 4));
	sink(shl32(3736443321, 2));
	sink(shl32(1913328227, 22));
	sink(shl32(2379399255, 15));
	sink(shl32(3705096699, 23));
	sink(shl32(1469676134, 1));
	sink(shl32(2947472648, 16));
	sink(shl32(1143320945, 12));
	sink(shl32(2273817807, 4));
	sink(shl32(503715912, 9));
	sink(shl32(179833507, 13));
	sink(shl32(1464133235, 4));
	sink(shl32(3608553399, 17));
	sink(shl32(3562214148, 30));
	sink(shl32(1316933635, 5));
}

